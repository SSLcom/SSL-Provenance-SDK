"""Signer backed by an SSL.com eSigner credential via the CSC API."""

from __future__ import annotations

import base64
import hashlib
import logging
import ssl
from typing import Dict, List, Optional

import c2pa
import requests

from . import cose
from .csc_api import CscApi
from .errors import CscApiError
from .timestamp import request_time_stamp_token

logger = logging.getLogger(__name__)

#: Fixed allowance for everything in a COSE signature other than the
#: certificate chain and the RFC 3161 timestamp token: the raw signature itself,
#: the protected/unprotected header maps, and CBOR framing.
SIG_OVERHEAD_RESERVE = 1024

#: Allowance for the RFC 3161 timestamp token embedded as the ``sigTst2``
#: countersignature, which carries the TSA's own certificate chain. Deliberately
#: generous: under-reserving is a hard signing failure, not a graceful shrink.
TIMESTAMP_RESERVE = 10_000

#: ``sig_type`` of a CAWG identity assertion signed with an X.509 certificate.
CAWG_X509_SIG_TYPE = "cawg.x509.cose"

#: CSC signing-algorithm OIDs mapped to c2pa algorithm names.
_SIGNING_ALG_BY_OID = {
    "1.2.840.10045.4.3.2": "es256",
    "1.2.840.10045.4.3.3": "es384",
    "1.2.840.10045.4.3.4": "es512",
    "1.2.840.113549.1.1.11": "ps256",
    "1.2.840.113549.1.1.12": "ps384",
    "1.2.840.113549.1.1.13": "ps512",
}

_C2PA_SIGNING_ALG = {
    "es256": c2pa.C2paSigningAlg.ES256,
    "es384": c2pa.C2paSigningAlg.ES384,
    "es512": c2pa.C2paSigningAlg.ES512,
    "ps256": c2pa.C2paSigningAlg.PS256,
    "ps384": c2pa.C2paSigningAlg.PS384,
    "ps512": c2pa.C2paSigningAlg.PS512,
}


def map_signing_alg(oid: str) -> str:
    """Map a CSC algorithm OID to a c2pa algorithm name; unknown OIDs fall back
    to ``es256``."""
    return _SIGNING_ALG_BY_OID.get(oid, "es256")


class CscSigner:
    """Signs C2PA claims and CAWG identity payloads with an eSigner credential.

    Every signature is one CSC round-trip pair: ``credentials/authorize`` for a
    SAD over the SHA-256 digest, then ``signatures/signHash``.
    """

    def __init__(
        self,
        api: CscApi,
        credential_id: str,
        certs_der: List[bytes],
        signature_algorithm: str,
        tsa_url: Optional[str] = None,
        tsa_headers: Optional[Dict[str, str]] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.api = api
        self.credential_id = credential_id
        self.certs_der = list(certs_der)
        #: Algorithm OID sent to the CSC API as ``signAlgo``.
        self.sig_algo = signature_algorithm
        #: c2pa algorithm name (``es256``, ``ps256``, ...).
        self.signing_alg = map_signing_alg(signature_algorithm)
        self.tsa_url = tsa_url
        self.tsa_headers = dict(tsa_headers or {})
        self._session = session
        #: Last exception raised while signing. c2pa only sees a failed
        #: callback, so this keeps the real cause for error reporting.
        self.last_error: Optional[BaseException] = None

    @property
    def c2pa_signing_alg(self) -> c2pa.C2paSigningAlg:
        return _C2PA_SIGNING_ALG[self.signing_alg]

    def reserve_bytes(self) -> int:
        """Upper bound on the size of a COSE signature produced by this signer.

        Sizes the CAWG identity assertion, whose space must be claimed before
        the signature exists; c2pa fills the slack with zero padding. Derived
        from the actual certificate chain so the padding stays proportional to
        what the signature needs. Overshooting only wastes bytes; undershooting
        fails the sign call outright.
        """
        cert_chain_len = sum(len(c) for c in self.certs_der)
        return SIG_OVERHEAD_RESERVE + cert_chain_len + TIMESTAMP_RESERVE

    def certs_pem(self) -> str:
        """The certificate chain as concatenated PEM, end-entity first."""
        return "".join(ssl.DER_cert_to_PEM_cert(der) for der in self.certs_der)

    def sign(self, data: bytes) -> bytes:
        """Sign ``data`` through the CSC API and return the raw signature."""
        try:
            hash_b64 = base64.b64encode(hashlib.sha256(data).digest()).decode("ascii")
            hashes = [hash_b64]

            sad = self.api.get_credentials_authorize(self.credential_id, 1, hashes)
            sigs = self.api.sign_hash(self.credential_id, sad, hashes, self.sig_algo)

            if not sigs:
                raise CscApiError("no signature returned")
            try:
                return base64.b64decode(sigs[0], validate=True)
            except ValueError as e:
                raise CscApiError(str(e), prefix="Base64 decode error") from e
        except BaseException as e:
            self.last_error = e
            raise

    def to_c2pa_signer(self, tsa_url: Optional[str]) -> c2pa.Signer:
        """A c2pa claim signer that calls back into :meth:`sign`.

        ``tsa_url`` is the timestamp URL c2pa should contact. It differs from
        :attr:`tsa_url` when TSA headers are routed through a
        :class:`~ssl_provenance_sdk.timestamp.TsaForwarder`.
        """
        return c2pa.Signer.from_callback(
            self.sign, self.c2pa_signing_alg, self.certs_pem(), tsa_url or None
        )

    def time_stamp(self, message: bytes) -> bytes:
        """RFC 3161 ``TimeStampToken`` over ``message`` from the configured TSA."""
        if not self.tsa_url:
            raise RuntimeError("no TSA URL configured")
        return request_time_stamp_token(
            self.tsa_url, message, self.tsa_headers, self._session
        )

    def identity_signature(self, signer_payload: bytes) -> bytes:
        """The ``cawg.x509.cose`` signature for a CAWG ``signer_payload``:
        a detached COSE_Sign1 with this credential's chain and a ``sigTst2``
        timestamp."""
        try:
            return cose.sign1_detached(
                signer_payload,
                self.signing_alg,
                self.certs_der,
                self.sign,
                self.time_stamp if self.tsa_url else None,
            )
        except BaseException as e:
            self.last_error = e
            raise
