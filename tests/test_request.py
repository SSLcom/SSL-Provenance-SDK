"""Request validation (header-equivalent checks) and media helpers."""

import json
import struct

import pytest

from ssl_provenance_sdk import (
    CawgUnsupportedError,
    InvalidCawgRoleError,
    InvalidCustomAssertionError,
    MissingCredentialIdError,
    ProvenanceClient,
    SignRequest,
    UnsupportedMediaTypeError,
)
from ssl_provenance_sdk.assertions import encode_base64url
from ssl_provenance_sdk.media import JXL_CONTAINER_SIG, c2pa_format, wrap_jxl_codestream


def _request(**overrides) -> SignRequest:
    req = (
        ProvenanceClient()
        .new_request()
        .set_access_token("token")
        .set_c2pa_certificate_id("cred-1")
        .set_content_type("image/jpeg")
        .set_asset(b"\xff\xd8\xff")
    )
    for name, value in overrides.items():
        getattr(req, name)(value)
    return req


def test_access_token_gets_bearer_scheme():
    assert SignRequest().set_access_token("abc").access_token == "Bearer abc"
    assert SignRequest().set_access_token("Bearer abc").access_token == "Bearer abc"
    assert SignRequest().set_access_token("bearer abc").access_token == "bearer abc"


def test_valid_request_normalizes_inputs():
    plan = _request(
        set_content_type="image/jpeg; charset=utf-8",
        set_cawg_certificate_id="  cred-2 ",
        add_cawg_role="cawg.creator, cawg.editor",
    ).validate()
    assert plan.content_type == "image/jpeg"
    assert plan.cawg_credential_id == "cred-2"
    assert plan.cawg_roles == ["cawg.creator", "cawg.editor"]


def test_missing_credential_id():
    with pytest.raises(MissingCredentialIdError) as excinfo:
        _request(set_c2pa_certificate_id="").validate()
    assert excinfo.value.status_code == 400
    assert excinfo.value.to_dict() == {"error": "credential ID not present in request"}


def test_unsupported_media_type():
    with pytest.raises(UnsupportedMediaTypeError) as excinfo:
        _request(set_content_type="text/plain").validate()
    assert excinfo.value.status_code == 415
    assert str(excinfo.value) == "Unsupported media type: text/plain"


def test_cawg_rejected_for_pdf():
    with pytest.raises(CawgUnsupportedError) as excinfo:
        _request(set_content_type="application/pdf", set_cawg_certificate_id="c").validate()
    assert excinfo.value.status_code == 422


def test_cawg_role_requires_cawg_credential():
    with pytest.raises(InvalidCawgRoleError) as excinfo:
        _request(add_cawg_role="cawg.creator,cawg.editor").validate()
    assert excinfo.value.status_code == 400
    assert str(excinfo.value) == (
        "CAWG-Role requires CAWG-Certificate-Id: cawg.creator, cawg.editor"
    )

    # A blank CAWG credential counts as absent.
    with pytest.raises(InvalidCawgRoleError):
        _request(set_cawg_certificate_id="  ", add_cawg_role="cawg.creator").validate()


def test_trust_anchors_shared_in_memory():
    pem = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
    assert ProvenanceClient().trust_anchors is None

    # One in-memory bundle, many clients; no client copies or re-reads it.
    clients = [ProvenanceClient(trust_anchors=pem), ProvenanceClient().set_trust_anchors(pem)]
    for client in clients:
        assert client.trust_anchors is pem
        settings = json.loads(client.c2pa_settings_json())
        assert settings["trust"]["trust_anchors"] == pem

    assert clients[0].set_trust_anchors(None).trust_anchors is None
    assert clients[1].trust_anchors is pem


def test_custom_assertion_setters():
    req = (
        SignRequest()
        .add_custom_assertion("com.example.a", {"x": 1})
        .add_custom_assertion("com.example.b", [1, 2], kind="Json", created=True)
        .add_custom_assertion_definition([{"label": "com.example.c", "data": None}])
        .add_encoded_custom_assertion(encode_base64url({"label": "com.example.d", "data": 4}))
    )
    assert req.custom_assertions == [
        {"label": "com.example.a", "data": {"x": 1}},
        {"label": "com.example.b", "data": [1, 2], "kind": "Json", "created": True},
        {"label": "com.example.c", "data": None},
        {"label": "com.example.d", "data": 4},
    ]

    # Invalid definitions fail at the setter, before any network call.
    with pytest.raises(InvalidCustomAssertionError):
        SignRequest().add_custom_assertion_definition({"label": "com.example.x"})
    with pytest.raises(InvalidCustomAssertionError):
        SignRequest().add_custom_assertion(" ", {})


def test_c2pa_format():
    assert c2pa_format("audio/mp4") == "video/mp4"
    assert c2pa_format("image/png") == "image/png"


def test_wrap_jxl_codestream():
    codestream = b"\xff\x0a" + b"\x00" * 10
    wrapped = wrap_jxl_codestream(codestream)
    assert wrapped.startswith(JXL_CONTAINER_SIG)
    assert wrapped[12:32] == b"\x00\x00\x00\x14ftypjxl \x00\x00\x00\x00jxl "
    assert struct.unpack(">I", wrapped[32:36])[0] == 8 + len(codestream)
    assert wrapped[36:40] == b"jxlc"
    assert wrapped[40:] == codestream

    # Containers and non-JXL data pass through unchanged.
    assert wrap_jxl_codestream(wrapped) == wrapped
    assert wrap_jxl_codestream(b"not jxl") == b"not jxl"


def test_asset_must_be_bytes():
    assert SignRequest().set_asset(bytearray(b"ab")).asset == b"ab"
    assert SignRequest().set_asset(memoryview(b"ab")).asset == b"ab"
    with pytest.raises(TypeError):
        SignRequest().set_asset("photo.jpg")
