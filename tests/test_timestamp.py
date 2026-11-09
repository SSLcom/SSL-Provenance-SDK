"""Timestamp request encoding, the TSA forwarder, and (opt-in) a live TSA run."""

import hashlib
import io
import json
import os

import c2pa
import pytest
import requests
from asn1crypto import tsp

from conftest import CSC_ENDPOINT, TOKEN
from ssl_provenance_sdk import MissingTsaTokenError, ProvenanceClient
from ssl_provenance_sdk.environments import tsa_requires_token
from ssl_provenance_sdk.manifest import build_c2pa_settings_json
from ssl_provenance_sdk.timestamp import TsaForwarder, build_time_stamp_request

#: Set to a TSA URL (or "1" for SSL.com's default) to run the live TSA test.
LIVE_TSA = os.environ.get("SSL_PROVENANCE_LIVE_TSA")
LIVE_TSA_URL = (
    LIVE_TSA if LIVE_TSA and LIVE_TSA.startswith("http") else "https://ts-c2pa.ssl.com/ecc"
)
#: Bearer token for the live TSA; required by the SSL.com TSA.
LIVE_TSA_TOKEN = os.environ.get("SSL_PROVENANCE_TSA_TOKEN")


def test_time_stamp_request_encoding():
    req = tsp.TimeStampReq.load(build_time_stamp_request(b"hello"))
    assert req["version"].native == "v1"
    imprint = req["message_imprint"]
    assert imprint["hash_algorithm"]["algorithm"].native == "sha256"
    assert imprint["hashed_message"].native == hashlib.sha256(b"hello").digest()
    assert req["cert_req"].native is True
    assert req["nonce"].native is not None


class _Upstream:
    def __init__(self):
        self.calls = []

    def post(self, url, data=None, headers=None, timeout=None):
        self.calls.append((url, data, headers))
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b"tsa-reply"
        return resp


def test_forwarder_adds_headers():
    upstream = _Upstream()
    with TsaForwarder("http://tsa.test/rsa", {"Authorization": "Bearer t"}, upstream) as fwd:
        resp = requests.post(
            fwd.url,
            data=b"query",
            headers={"Content-Type": "application/timestamp-query"},
            timeout=5,
        )
    assert resp.status_code == 200
    assert resp.content == b"tsa-reply"
    url, body, headers = upstream.calls[0]
    assert url == "http://tsa.test/rsa"
    assert body == b"query"
    assert headers["Authorization"] == "Bearer t"
    assert headers["Content-Type"] == "application/timestamp-query"


@pytest.mark.skipif(not LIVE_TSA, reason="set SSL_PROVENANCE_LIVE_TSA=1 (or a TSA URL) to use a live TSA")
@pytest.mark.parametrize("use_token", [False, True], ids=["no-token", "token"])
def test_live_tsa_timestamps_claim_and_identity(csc, pki, png_bytes, use_token):
    if use_token and not LIVE_TSA_TOKEN:
        pytest.skip("set SSL_PROVENANCE_TSA_TOKEN to run with a TSA token")
    if not use_token and tsa_requires_token(LIVE_TSA_URL):
        pytest.skip("this TSA requires a bearer token")
    bearer = LIVE_TSA_TOKEN if use_token else None
    client = (
        ProvenanceClient()
        .set_csc_endpoint(CSC_ENDPOINT)
        .set_tsa_url(LIVE_TSA_URL)
        .set_tsa_token(bearer)  # exercises the forwarder when set
        .set_trust_anchors(pki["anchors"])
        .set_session(csc)
    )
    # The CSC fake only answers CSC calls; send TSA traffic to the network.
    original_post = csc.post
    tsa_calls = []

    def post(url, headers=None, data=None, timeout=None):
        if url.startswith(CSC_ENDPOINT):
            return original_post(url, headers=headers, data=data, timeout=timeout)
        tsa_calls.append(headers)
        return requests.post(url, headers=headers, data=data, timeout=timeout)

    csc.post = post

    signed = (
        client.new_request()
        .set_access_token(TOKEN)
        .set_c2pa_certificate_id("claim-cred")
        .set_cawg_certificate_id("identity-cred")
        .add_cawg_role("cawg.creator")
        .set_content_type("image/png")
        .set_asset(png_bytes)
        .sign()
    )

    ctx = c2pa.Context(
        c2pa.Settings.from_json(build_c2pa_settings_json(pki["anchors"]))
    )
    reader = c2pa.Reader("image/png", io.BytesIO(signed), None, context=ctx)
    store = json.loads(reader.json())
    reader.close()
    active = store["manifests"][store["active_manifest"]]

    # Claim signature carries a timestamp.
    assert active["signature_info"].get("time")

    # The identity signature's TSA request always goes through the session;
    # c2pa sends the claim's itself, through the session only when the bearer
    # token routes it via the forwarder. Each carries the token when set.
    assert len(tsa_calls) == (2 if bearer else 1)
    for headers in tsa_calls:
        assert headers.get("Authorization") == (f"Bearer {bearer}" if bearer else None)

    # Identity signature carries a sigTst2 countersignature.
    identity = next(a for a in active["assertions"] if a["label"].startswith("cawg.identity"))
    assert identity["data"]["signer_payload"]["sig_type"] == "cawg.x509.cose"
    codes = {
        r["code"]
        for r in store["validation_results"]["activeManifest"].get("success", [])
    }
    assert any(code.startswith("timeStamp.") for code in codes), codes
