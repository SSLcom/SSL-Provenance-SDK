"""Trust-list download helper (no network: a fake session answers GETs)."""

import pytest
import requests

from ssl_provenance_sdk import ProvenanceClient, TrustListDownloadError, download_trust_anchors

SIGNING_PEM = "-----BEGIN CERTIFICATE-----\nSIGN\n-----END CERTIFICATE-----"
TSA_PEM = "-----BEGIN CERTIFICATE-----\nTSA\n-----END CERTIFICATE-----\n"


class FakeResponse:
    def __init__(self, status: int, text: str) -> None:
        self.status_code = status
        self.ok = status < 400
        self.text = text


class FakeSession:
    def __init__(self, pages: dict) -> None:
        self.pages = pages
        self.requested = []

    def get(self, url, timeout=None):
        self.requested.append(url)
        page = self.pages.get(url)
        if isinstance(page, Exception):
            raise page
        return page or FakeResponse(404, "not found")


def test_download_merges_both_lists_for_shared_clients():
    session = FakeSession(
        {"https://t/sign.pem": FakeResponse(200, SIGNING_PEM), "https://t/tsa.pem": FakeResponse(200, TSA_PEM)}
    )
    pem = download_trust_anchors("https://t/sign.pem", "https://t/tsa.pem", session=session)
    assert pem == SIGNING_PEM + "\n" + TSA_PEM
    assert session.requested == ["https://t/sign.pem", "https://t/tsa.pem"]

    a = ProvenanceClient(trust_anchors=pem)
    b = ProvenanceClient().set_trust_anchors(pem)
    assert a.trust_anchors is pem and b.trust_anchors is pem


def test_download_without_tsa_list():
    session = FakeSession({"https://t/sign.pem": FakeResponse(200, SIGNING_PEM)})
    assert download_trust_anchors("https://t/sign.pem", None, session=session) == SIGNING_PEM + "\n"
    assert session.requested == ["https://t/sign.pem"]


@pytest.mark.parametrize(
    "page",
    [FakeResponse(500, "boom"), FakeResponse(200, "<html>not pem</html>"), requests.ConnectionError("down")],
)
def test_download_failure(page):
    session = FakeSession({"https://t/sign.pem": FakeResponse(200, SIGNING_PEM), "https://t/tsa.pem": page})
    with pytest.raises(TrustListDownloadError) as excinfo:
        download_trust_anchors("https://t/sign.pem", "https://t/tsa.pem", session=session)
    assert excinfo.value.status_code == 502
    assert "https://t/tsa.pem" in str(excinfo.value)
