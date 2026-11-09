"""Downloading and merging the C2PA trust lists.

The SDK never calls this on its own: signing never touches the network for
trust lists. Your application calls :func:`download_trust_anchors` once (at
startup, or on a timer to refresh), keeps the returned string in memory and
passes the same string to every client::

    trust_anchors = download_trust_anchors(TRUST_LIST_URL, TSA_TRUST_LIST_URL)
    client_a = ProvenanceClient(trust_anchors=trust_anchors)
    client_b = ProvenanceClient().set_trust_anchors(trust_anchors)
"""

from __future__ import annotations

import logging
from typing import Optional

import requests

from .errors import TrustListDownloadError

logger = logging.getLogger(__name__)

#: Official C2PA trust lists (PEM bundles of root anchors) published by the
#: c2pa-org conformance-public repository.
C2PA_TRUST_LIST_URL = (
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/"
    "trust-list/C2PA-TRUST-LIST.pem"
)
C2PA_TSA_TRUST_LIST_URL = (
    "https://raw.githubusercontent.com/c2pa-org/conformance-public/main/"
    "trust-list/C2PA-TSA-TRUST-LIST.pem"
)


def download_trust_anchors(
    trust_list_url: str = C2PA_TRUST_LIST_URL,
    tsa_trust_list_url: Optional[str] = C2PA_TSA_TRUST_LIST_URL,
    *,
    session: Optional[requests.Session] = None,
    timeout: Optional[float] = 30,
) -> str:
    """Download the signing trust list and the TSA trust list and merge them
    into one in-memory PEM bundle for :class:`ProvenanceClient`
    (``ProvenanceClient(trust_anchors=...)`` or
    :meth:`ProvenanceClient.set_trust_anchors`).

    ``tsa_trust_list_url=None`` downloads only the signing list. Nothing is
    written to disk. Raises :class:`TrustListDownloadError` if a list can't be
    downloaded or isn't a PEM bundle.
    """
    session = session or requests.Session()

    def fetch(url: str) -> str:
        try:
            resp = session.get(url, timeout=timeout)
        except requests.RequestException as e:
            raise TrustListDownloadError(url, str(e)) from e
        if not resp.ok:
            raise TrustListDownloadError(url, f"HTTP {resp.status_code}")
        if "BEGIN CERTIFICATE" not in resp.text:
            raise TrustListDownloadError(url, "response is not a PEM bundle")
        return resp.text if resp.text.endswith("\n") else resp.text + "\n"

    bundle = fetch(trust_list_url)
    if tsa_trust_list_url:
        bundle += fetch(tsa_trust_list_url)
    logger.info(
        "downloaded C2PA trust anchors (%d certificates)", bundle.count("BEGIN CERTIFICATE")
    )
    return bundle
