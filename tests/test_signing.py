"""End-to-end signing through c2pa against the fake CSC API (no TSA)."""

import io
import json

import c2pa
import cbor2
import pytest

from conftest import CSC_ENDPOINT, TOKEN
from ssl_provenance_sdk import NoCredentialError, ProvenanceClient
from ssl_provenance_sdk.manifest import build_c2pa_settings_json


@pytest.fixture()
def client(csc, pki):
    return (
        ProvenanceClient()
        .set_csc_endpoint(CSC_ENDPOINT)
        .set_tsa_url(None)
        .set_tsa_token(None)
        .set_trust_anchors(pki["anchors"])
        .set_session(csc)
    )


def _read(pki, fmt, data, manifest_data=None):
    settings = json.loads(build_c2pa_settings_json(pki["anchors"]))
    # CAWG identity credentials are checked against their own trust list.
    settings["trust"]["anchors"] = [
        {
            "trust_anchors": pki["anchors"],
            "trust_uri": "https://sdk.test/cawg",
            "trust_kind": "cawg",
            "trust_config": None,
            "allowed_list": None,
            "trusted_ica_issuers": None,
        }
    ]
    ctx = c2pa.Context(c2pa.Settings.from_json(json.dumps(settings)))
    reader = c2pa.Reader(fmt, io.BytesIO(data), manifest_data, context=ctx)
    try:
        return json.loads(reader.json())
    finally:
        reader.close()


def _active(store):
    return store["manifests"][store["active_manifest"]]


def _failures(store):
    results = store.get("validation_results", {}).get("activeManifest", {})
    return results.get("failure", [])


def test_sign_new_manifest(client, pki, png_bytes):
    signed = (
        client.new_request()
        .set_access_token(TOKEN)
        .set_c2pa_certificate_id("claim-cred")
        .set_content_type("image/png")
        .set_asset(png_bytes)
        .add_custom_assertion("com.example.review", {"reviewer": "jane", "rating": 5})
        .sign()
    )
    assert isinstance(signed, bytes)
    assert signed != png_bytes

    store = _read(pki, "image/png", signed)
    assert _failures(store) == []
    assert store["validation_state"] == "Trusted"

    manifest = _active(store)
    assert manifest["claim_generator_info"][0]["name"] == "SSL Provenance API"
    assert manifest["signature_info"]["common_name"] == "SDK Test Claim Signer"

    ingredient = manifest["ingredients"][0]
    assert ingredient["relationship"] == "parentOf"
    assert ingredient["title"] == "image/png"

    labels = {a["label"]: a for a in manifest["assertions"]}
    actions = labels["c2pa.actions.v2"]["data"]["actions"]
    opened = [a for a in actions if a["action"] == "c2pa.opened"]
    assert opened and opened[0]["softwareAgent"]["name"] == "SSL Provenance API"
    assert opened[0]["parameters"]["ingredients"], "c2pa.opened must reference the ingredient"
    assert labels["com.example.review"]["data"] == {"reviewer": "jane", "rating": 5}


def test_resign_adds_to_existing_store(client, pki, png_bytes):
    def sign(data):
        return (
            client.new_request()
            .set_access_token(TOKEN)
            .set_c2pa_certificate_id("claim-cred")
            .set_content_type("image/png")
            .set_asset(data)
            .sign()
        )

    twice = sign(sign(png_bytes))
    store = _read(pki, "image/png", twice)
    assert _failures(store) == []
    assert len(store["manifests"]) == 2

    parent = _active(store)["ingredients"][0]
    assert parent["relationship"] == "parentOf"
    assert parent.get("active_manifest") in store["manifests"]


@pytest.mark.parametrize("cawg_cred", ["identity-cred", "claim-cred"])
def test_sign_with_cawg_identity(client, pki, png_bytes, cawg_cred):
    signed = (
        client.new_request()
        .set_access_token(TOKEN)
        .set_c2pa_certificate_id("claim-cred")
        .set_cawg_certificate_id(cawg_cred)
        .add_cawg_role("cawg.creator,cawg.editor")
        .set_content_type("image/png")
        .set_asset(png_bytes)
        .sign()
    )

    store = _read(pki, "image/png", signed)
    assert _failures(store) == []

    identity = [a for a in _active(store)["assertions"] if a["label"].startswith("cawg.identity")]
    assert len(identity) == 1
    data = identity[0]["data"]
    signer_payload = data["signer_payload"]
    assert signer_payload["sig_type"] == "cawg.x509.cose"
    assert signer_payload["role"] == ["cawg.creator", "cawg.editor"]
    # The verified identity carries the identity credential's subject.
    assert "SDK Test" in json.dumps(data)


def test_identity_signature_is_cose_sign1(pki):
    from ssl_provenance_sdk.csc_api import CscApi
    from conftest import FakeCscSession
    from ssl_provenance_sdk.signer import CscSigner

    chain, _ = pki["credentials"]["identity-cred"]
    api = CscApi(TOKEN, CSC_ENDPOINT, FakeCscSession(pki["credentials"]))
    signer = CscSigner(api, "identity-cred", chain, "1.2.840.10045.4.3.2")

    cose = cbor2.loads(signer.identity_signature(cbor2.dumps({"x": 1})))
    assert cose.tag == 18
    protected, unprotected, payload, signature = cose.value
    assert cbor2.loads(protected) == {1: -7, 33: chain}
    assert unprotected == {}  # no TSA configured
    assert payload is None  # detached
    assert len(signature) == 64  # P1363 r||s for P-256


def test_sign_pdf_returns_sidecar(client, pki, pdf_bytes):
    sidecar = (
        client.new_request()
        .set_access_token(TOKEN)
        .set_c2pa_certificate_id("claim-cred")
        .set_content_type("application/pdf")
        .set_asset(pdf_bytes)
        .add_custom_assertion("com.example.review", {"rating": 5})
        .sign()
    )
    assert isinstance(sidecar, bytes)
    # The sidecar is a bare C2PA manifest store (a JUMBF superbox), not a PDF.
    assert sidecar[4:8] == b"jumb"

    store = _read(pki, "application/pdf", pdf_bytes, manifest_data=sidecar)
    manifest = _active(store)
    labels = [a["label"] for a in manifest["assertions"]]
    assert "com.example.review" in labels
    assert manifest["ingredients"][0]["title"] == "application/pdf"


def test_unknown_credential_is_no_credential_error(client, png_bytes):
    with pytest.raises(NoCredentialError) as excinfo:
        (
            client.new_request()
            .set_access_token(TOKEN)
            .set_c2pa_certificate_id("missing")
            .set_content_type("image/png")
            .set_asset(png_bytes)
            .sign()
        )
    assert excinfo.value.status_code == 500
    assert "unknown credential" in str(excinfo.value)
