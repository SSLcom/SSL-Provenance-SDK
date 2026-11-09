"""Input parsing: signing algorithms, CAWG roles, custom assertions and manifest definitions."""

import base64
import json

import c2pa
import pytest

from ssl_provenance_sdk.assertions import (
    encode_base64url,
    parse_cawg_roles,
    parse_encoded_custom_assertions,
)
from ssl_provenance_sdk.errors import InvalidCustomAssertionError
from ssl_provenance_sdk.manifest import MANIFEST_JSON, MANIFEST_JSON_EDIT, manifest_definition
from ssl_provenance_sdk.signer import map_signing_alg


def test_signing_alg_oid_mapping():
    assert map_signing_alg("1.2.840.10045.4.3.2") == "es256"
    assert map_signing_alg("1.2.840.10045.4.3.3") == "es384"
    assert map_signing_alg("1.2.840.10045.4.3.4") == "es512"
    assert map_signing_alg("1.2.840.113549.1.1.11") == "ps256"
    assert map_signing_alg("1.2.840.113549.1.1.12") == "ps384"
    assert map_signing_alg("1.2.840.113549.1.1.13") == "ps512"
    # Unknown OIDs fall back to es256.
    assert map_signing_alg("9.9.9") == "es256"


def test_cawg_roles_parsing():
    # No values at all.
    assert parse_cawg_roles([]) == []

    # Single value.
    assert parse_cawg_roles(["cawg.creator"]) == ["cawg.creator"]

    # Comma-separated, with surrounding whitespace and an empty entry that
    # should be dropped.
    assert parse_cawg_roles(["cawg.creator, cawg.editor ,,"]) == [
        "cawg.creator",
        "cawg.editor",
    ]

    # Repeated values, each single-valued.
    assert parse_cawg_roles(["cawg.creator", "cawg.editor"]) == [
        "cawg.creator",
        "cawg.editor",
    ]

    # Repeated values where one is itself comma-separated.
    assert parse_cawg_roles(["cawg.creator,cawg.editor", "cawg.producer"]) == [
        "cawg.creator",
        "cawg.editor",
        "cawg.producer",
    ]


REVIEW = {"label": "com.example.review", "data": {"rating": 5}}
NOTES = {
    "label": "com.example.notes",
    "data": {"text": "héllo"},
    "kind": "Json",
    "created": True,
}


def test_custom_assertion_parsing():
    # No values at all.
    assert parse_encoded_custom_assertions([]) == []

    # One value holding one assertion object.
    assert parse_encoded_custom_assertions([encode_base64url(REVIEW)]) == [REVIEW]

    # One value holding a JSON array of assertions.
    assert parse_encoded_custom_assertions([encode_base64url([REVIEW, NOTES])]) == [
        REVIEW,
        NOTES,
    ]

    # Repeated values, and a comma-separated value, accumulate in order.
    values = [
        f"{encode_base64url(REVIEW)}, {encode_base64url(NOTES)}",
        encode_base64url(REVIEW),
    ]
    assert parse_encoded_custom_assertions(values) == [REVIEW, NOTES, REVIEW]

    # Padding is optional: the same payload without `=` padding decodes.
    unpadded = encode_base64url(REVIEW).rstrip("=")
    assert parse_encoded_custom_assertions([unpadded]) == [REVIEW]


def _bad(value: str) -> str:
    with pytest.raises(InvalidCustomAssertionError) as excinfo:
        parse_encoded_custom_assertions([value])
    assert excinfo.value.status_code == 400
    return str(excinfo.value)


def test_custom_assertion_rejects_bad_input():
    # Not base64url at all (`+` and `/` belong to the standard alphabet only).
    assert "base64url" in _bad("not base64!")
    std = base64.b64encode(b'{"label":"a??","data":{}}').decode()
    assert "+" in std or "/" in std
    assert "base64url" in _bad(std)

    # Valid base64url, but not JSON.
    assert "valid JSON" in _bad(base64.urlsafe_b64encode(b"not json").decode())

    # Valid JSON, but not an assertion definition.
    assert "JSON object" in _bad(encode_base64url("a string"))
    assert '"label"' in _bad(encode_base64url({"data": {}}))
    assert "must not be empty" in _bad(encode_base64url({"label": "  ", "data": {}}))
    assert '"data"' in _bad(encode_base64url({"label": "com.example.x"}))

    # An invalid entry inside an otherwise valid array is still rejected.
    assert '"data"' in _bad(
        encode_base64url(
            [{"label": "com.example.x", "data": {}}, {"label": "com.example.y"}]
        )
    )


def test_manifest_definition_merges_custom_assertions():
    custom = {"label": "com.example.review", "data": {"rating": 5}}

    # No custom assertions: the base is passed through untouched.
    assert manifest_definition(MANIFEST_JSON, []) == MANIFEST_JSON
    assert manifest_definition(MANIFEST_JSON_EDIT, []) == MANIFEST_JSON_EDIT

    # MANIFEST_JSON already declares c2pa.actions; custom assertions append to it.
    merged = manifest_definition(MANIFEST_JSON, [custom])
    assert len(merged["assertions"]) == 2
    assert merged["assertions"][0]["label"] == "c2pa.actions"
    assert merged["assertions"][1] == custom
    # The rest of the definition survives, and the base is not mutated.
    assert merged["claim_generator_info"][0]["name"] == "SSL Provenance API"
    assert len(MANIFEST_JSON["assertions"]) == 1

    # MANIFEST_JSON_EDIT declares no assertions list; one is created.
    merged = manifest_definition(MANIFEST_JSON_EDIT, [custom])
    assert merged["assertions"] == [custom]
    assert "assertions" not in MANIFEST_JSON_EDIT


def test_merged_manifest_definition_is_valid_for_builder():
    """The merged definition must still be accepted by the c2pa Builder."""
    custom = [
        {"label": "com.example.cbor", "data": {"rating": 5}},
        {
            "label": "com.example.json",
            "data": {"text": "hello"},
            "kind": "Json",
            "created": True,
        },
    ]
    for base in (MANIFEST_JSON, MANIFEST_JSON_EDIT):
        definition = manifest_definition(base, custom)
        builder = c2pa.Builder(json.dumps(definition))
        builder.close()
