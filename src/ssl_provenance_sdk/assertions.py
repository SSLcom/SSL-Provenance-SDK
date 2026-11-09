"""Parsing and validation of CAWG roles and caller-supplied custom assertions.

These accept the same encodings as the ``CAWG-Role`` and
``C2PA-Custom-Assertion`` headers of the SSL.com Provenance API, so
values already prepared for the HTTP API can be passed to the SDK unchanged.
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Any, Iterable, List

from .errors import InvalidCustomAssertionError

_BASE64URL_RE = re.compile(r"^[A-Za-z0-9_-]*={0,2}$")


def parse_cawg_roles(values: Iterable[str]) -> List[str]:
    """Flatten ``CAWG-Role``-style values into a list of named-actor roles.

    Each value may itself be comma-separated (``"cawg.creator,cawg.editor"``);
    entries are trimmed and empty ones dropped. Role values are passed through
    as-is: neither this function nor c2pa validates them against a fixed
    vocabulary, so extension/custom role URIs are allowed (CAWG identity spec
    §5.1.2, "Named actor roles": https://cawg.io/identity/1.2/).
    """
    return [
        role
        for value in values
        for role in (part.strip() for part in value.split(","))
        if role
    ]


def decode_base64url(value: str) -> bytes:
    """Decode base64url (RFC 4648 §5) with or without ``=`` padding.

    Rejects the standard alphabet's ``+`` and ``/`` so that a value encoded
    with the wrong variant fails loudly instead of decoding to garbage.
    """
    if not _BASE64URL_RE.match(value):
        raise ValueError("invalid character in base64url input")

    stripped = value.rstrip("=")
    if value != stripped and len(value) % 4 != 0:
        raise ValueError("invalid base64url padding")
    if len(stripped) % 4 == 1:
        raise ValueError("invalid base64url length")

    padded = stripped + "=" * (-len(stripped) % 4)
    try:
        return base64.urlsafe_b64decode(padded)
    except binascii.Error as e:
        raise ValueError(str(e)) from e


def encode_base64url(definition: Any) -> str:
    """base64url-encode a JSON assertion definition (or list of them), the way
    a caller of the HTTP API builds a ``C2PA-Custom-Assertion`` header value."""
    raw = json.dumps(definition, separators=(",", ":"), ensure_ascii=False)
    return base64.urlsafe_b64encode(raw.encode("utf-8")).decode("ascii")


def parse_encoded_custom_assertions(values: Iterable[str]) -> List[dict]:
    """Decode ``C2PA-Custom-Assertion``-style values into assertion definitions.

    Each value is one or more comma-separated base64url-encoded JSON documents
    (base64url's alphabet never contains a comma, so splitting on it is
    unambiguous). Each document is a single assertion definition object or a
    JSON array of them.
    """
    assertions: List[dict] = []

    for raw in values:
        for encoded in (part.strip() for part in raw.split(",")):
            if not encoded:
                continue
            try:
                decoded = decode_base64url(encoded)
            except ValueError as e:
                raise InvalidCustomAssertionError(
                    f"value is not valid base64url: {e}"
                ) from e
            try:
                document = json.loads(decoded.decode("utf-8"))
            except (UnicodeDecodeError, ValueError) as e:
                raise InvalidCustomAssertionError(
                    f"decoded value is not valid JSON: {e}"
                ) from e

            assertions.extend(normalize_custom_assertions(document))

    return assertions


def normalize_custom_assertions(document: Any) -> List[dict]:
    """Validate a decoded assertion definition, or a list of them."""
    if isinstance(document, list):
        return [validate_custom_assertion(item) for item in document]
    return [validate_custom_assertion(document)]


def validate_custom_assertion(value: Any) -> dict:
    """Check that a custom assertion has the envelope c2pa requires: a JSON
    object with a non-empty string ``label`` and a ``data`` member.

    Only the envelope is validated. The label vocabulary and the shape of
    ``data`` are the caller's to define; c2pa has the final say at sign time.
    """
    if not isinstance(value, dict):
        raise InvalidCustomAssertionError("assertion must be a JSON object")

    label = value.get("label")
    if not isinstance(label, str):
        raise InvalidCustomAssertionError('assertion is missing a string "label"')
    if not label.strip():
        raise InvalidCustomAssertionError('assertion "label" must not be empty')

    if "data" not in value:
        raise InvalidCustomAssertionError('assertion is missing "data"')

    return value
