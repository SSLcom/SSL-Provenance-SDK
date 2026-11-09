"""Client for SSL.com's CSC (Cloud Signature Consortium) API v0."""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any, List, Optional, Sequence, Tuple

import requests

from .errors import CscApiError


@dataclass
class CredentialInfo:
    """Certificate chain and signing algorithm of an eSigner credential."""

    #: Certificate chain, each entry a DER-encoded X.509 certificate
    #: (end-entity first).
    certs: List[bytes]
    #: Signing algorithm OID reported by the CSC API (``key.algo[0]``).
    signature_algorithm: str


class CscApi:
    """Thin wrapper over the CSC API endpoints used for signing.

    ``access_token`` is sent verbatim as the ``Authorization`` header, so it
    must include the scheme (``"Bearer <token>"``).
    """

    def __init__(
        self,
        access_token: str,
        endpoint: str,
        session: Optional[requests.Session] = None,
        timeout: Optional[float] = None,
    ) -> None:
        self._access_token = access_token
        self._endpoint = endpoint
        self._session = session or requests.Session()
        self._timeout = timeout

    def _url(self, path: str) -> str:
        return f"{self._endpoint}{path}"

    def _post(self, path: str, body: dict) -> Tuple[int, Any]:
        try:
            resp = self._session.post(
                self._url(path),
                headers={
                    "content-type": "application/json",
                    "Authorization": self._access_token,
                },
                data=json.dumps(body),
                timeout=self._timeout,
            )
        except requests.RequestException as e:
            raise CscApiError(str(e), prefix="HTTP error") from e

        if not resp.content:
            return resp.status_code, {}
        try:
            return resp.status_code, resp.json()
        except ValueError as e:
            raise CscApiError(str(e), prefix="JSON error") from e

    @staticmethod
    def _api_error(payload: Any) -> CscApiError:
        return CscApiError(json.dumps(payload, separators=(",", ":")))

    def get_credential_info(self, credential_id: str) -> CredentialInfo:
        """Fetch the certificate chain and signing algorithm of a credential."""
        status, payload = self._post(
            "/csc/v0/credentials/info",
            {"credentialID": credential_id, "certificates": "chain"},
        )

        if status != 200:
            raise self._api_error(payload)

        cert_arr = _pointer(payload, "cert", "certificates")
        if not isinstance(cert_arr, list):
            raise CscApiError("missing cert.certificates")

        certs = []
        for entry in cert_arr:
            if not isinstance(entry, str):
                raise CscApiError("cert entry not a string")
            certs.append(_b64decode(entry))

        algos = _pointer(payload, "key", "algo")
        signature_algorithm = algos[0] if isinstance(algos, list) and algos else None
        if not isinstance(signature_algorithm, str):
            raise CscApiError("missing key.algo[0]")

        return CredentialInfo(certs=certs, signature_algorithm=signature_algorithm)

    def get_credentials_authorize(
        self,
        credential_id: str,
        num_signatures: int,
        hashes: Sequence[str],
        otp: Optional[str] = None,
    ) -> str:
        """Authorize signing ``num_signatures`` hashes; returns the SAD token."""
        body: dict = {
            "credentialID": credential_id,
            "numSignatures": num_signatures,
            "hash": list(hashes),
        }
        if otp is not None:
            body["OTP"] = otp

        status, payload = self._post("/csc/v0/credentials/authorize", body)

        if status != 200:
            raise self._api_error(payload)

        sad = payload.get("SAD") if isinstance(payload, dict) else None
        if not isinstance(sad, str):
            raise CscApiError("missing SAD", prefix="JSON error")
        return sad

    def sign_hash(
        self,
        credential_id: str,
        sad: str,
        hashes: Sequence[str],
        sig_algo: str,
    ) -> List[str]:
        """Sign one or more hashes; returns base64-encoded signature strings."""
        status, payload = self._post(
            "/csc/v0/signatures/signHash",
            {
                "credentialID": credential_id,
                "SAD": sad,
                "hash": list(hashes),
                "signAlgo": sig_algo,
            },
        )

        if status != 200:
            raise self._api_error(payload)

        sigs = payload.get("signatures") if isinstance(payload, dict) else None
        if not isinstance(sigs, list):
            raise CscApiError("missing signatures", prefix="JSON error")
        return sigs

    def is_otp_type_online(self, credential_id: str) -> bool:
        """``True`` when the credential uses explicit auth with an online OTP."""
        status, payload = self._post(
            "/csc/v0/credentials/info",
            {"credentialID": credential_id, "authInfo": True},
        )

        if status != 200:
            raise self._api_error(payload)

        auth_mode = payload.get("authMode") if isinstance(payload, dict) else None
        if not isinstance(auth_mode, str):
            raise CscApiError("missing authMode")

        if auth_mode == "implicit":
            return False

        otp_type = _pointer(payload, "OTP", "type")
        if not isinstance(otp_type, str):
            raise CscApiError("missing OTP.type")

        return auth_mode == "explicit" and otp_type == "online"

    def send_otp(self, credential_id: str) -> None:
        """Trigger an OTP to be sent to the user (expects HTTP 204 on success)."""
        status, payload = self._post(
            "/csc/v0/credentials/sendOTP", {"credentialID": credential_id}
        )

        if status != 204:
            raise self._api_error(payload)


def _pointer(value: Any, *keys: str) -> Any:
    """Walk nested dicts like ``serde_json::Value::pointer``; ``None`` if absent."""
    for key in keys:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _b64decode(value: str) -> bytes:
    try:
        return base64.b64decode(value, validate=True)
    except ValueError as e:
        raise CscApiError(str(e), prefix="Base64 decode error") from e
