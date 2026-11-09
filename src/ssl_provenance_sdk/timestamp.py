"""RFC 3161 timestamp authority (TSA) support.

Two consumers need a TSA:

* The C2PA claim signature. c2pa itself requests the timestamp, but its
  callback-signer API accepts only a TSA URL, not request headers. When a TSA
  bearer token is configured, :class:`TsaForwarder` runs a loopback HTTP
  forwarder that c2pa is pointed at instead; it relays each request to the
  real TSA with the ``Authorization`` header added.
* The CAWG identity assertion's COSE signature, which this SDK assembles
  itself (see :mod:`ssl_provenance_sdk.cose`) and timestamps with
  :func:`request_time_stamp_token`.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Optional

import requests
from asn1crypto import tsp

logger = logging.getLogger(__name__)

TIMESTAMP_QUERY_CONTENT_TYPE = "application/timestamp-query"

#: The TSA forwarder listens on loopback only.
_LOOPBACK_HOST = "127.0.0.1"


def bearer_headers(token: Optional[str]) -> Dict[str, str]:
    """``Authorization`` header for the TSA, or none when no token is set."""
    return {"Authorization": f"Bearer {token}"} if token else {}


def build_time_stamp_request(message: bytes) -> bytes:
    """DER ``TimeStampReq`` over SHA-256(``message``), with a random nonce and
    ``certReq`` set, matching c2pa's default request body."""
    request = tsp.TimeStampReq(
        {
            "version": "v1",
            "message_imprint": {
                "hash_algorithm": {"algorithm": "sha256"},
                "hashed_message": hashlib.sha256(message).digest(),
            },
            "nonce": int.from_bytes(secrets.token_bytes(8), "little"),
            "cert_req": True,
        }
    )
    return request.dump()


def post_time_stamp_request(
    url: str,
    body: bytes,
    headers: Optional[Dict[str, str]] = None,
    session: Optional[requests.Session] = None,
    timeout: Optional[float] = 30,
) -> bytes:
    """POST an RFC 3161 query and return the raw ``TimeStampResp`` bytes."""
    session = session or requests.Session()
    req_headers = {"Content-Type": TIMESTAMP_QUERY_CONTENT_TYPE}
    req_headers.update(headers or {})
    try:
        resp = session.post(url, data=body, headers=req_headers, timeout=timeout)
    except requests.RequestException as e:
        logger.error("TSA request failed: %s", e)
        raise RuntimeError(f"TSA request failed: {e}") from e

    if not resp.ok:
        logger.error("TSA request failed: TSA returned HTTP %s", resp.status_code)
        raise RuntimeError(f"TSA returned HTTP {resp.status_code}")

    logger.info("TSA response received: %d bytes", len(resp.content))
    return resp.content


def time_stamp_token_from_response(response: bytes) -> bytes:
    """Extract the DER ``TimeStampToken`` (a CMS ``ContentInfo``) from a
    ``TimeStampResp``; ``sigTst2`` carries only the token."""
    parsed = tsp.TimeStampResp.load(response)
    status = parsed["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise RuntimeError(f"TSA rejected the request (status: {status})")

    token = parsed["time_stamp_token"]
    if token.native is None:
        raise RuntimeError("invalid timestamp token")
    return token.dump(force=True)


def request_time_stamp_token(
    url: str,
    message: bytes,
    headers: Optional[Dict[str, str]] = None,
    session: Optional[requests.Session] = None,
) -> bytes:
    """Timestamp ``message`` and return the DER ``TimeStampToken``."""
    body = build_time_stamp_request(message)
    response = post_time_stamp_request(url, body, headers, session)
    return time_stamp_token_from_response(response)


class TsaForwarder:
    """Loopback HTTP forwarder that adds headers to c2pa's TSA requests.

    Use as a context manager; :attr:`url` is the address to hand to c2pa while
    it is running::

        with TsaForwarder(tsa_url, {"Authorization": "Bearer ..."}) as fwd:
            signer = Signer.from_callback(cb, alg, certs, fwd.url)
            ...
    """

    def __init__(
        self,
        target_url: str,
        headers: Dict[str, str],
        session: Optional[requests.Session] = None,
    ) -> None:
        self._target_url = target_url
        self._headers = dict(headers)
        self._session = session or requests.Session()
        self._server: Optional[ThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    @property
    def url(self) -> str:
        if self._server is None:
            raise RuntimeError("TsaForwarder is not running")
        return f"http://{_LOOPBACK_HOST}:{self._server.server_port}/"

    def __enter__(self) -> "TsaForwarder":
        forwarder = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 - http.server naming
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length)
                try:
                    payload = post_time_stamp_request(
                        forwarder._target_url,
                        body,
                        forwarder._headers,
                        forwarder._session,
                    )
                except Exception as e:  # noqa: BLE001 - surfaced to c2pa as a 502
                    message = str(e).encode()
                    self.send_response(502)
                    self.send_header("Content-Length", str(len(message)))
                    self.end_headers()
                    self.wfile.write(message)
                    return

                self.send_response(200)
                self.send_header("Content-Type", "application/timestamp-reply")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args) -> None:  # noqa: A002
                logger.debug("TSA forwarder: " + format, *args)

        self._server = ThreadingHTTPServer((_LOOPBACK_HOST, 0), Handler)
        self._server.daemon_threads = True
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="tsa-forwarder", daemon=True
        )
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join()
            self._thread = None
