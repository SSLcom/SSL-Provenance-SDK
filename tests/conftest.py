"""Fixtures: a throwaway PKI and an in-process fake of the CSC API."""

import base64
import datetime
import json
import struct
import zlib

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CSC_ENDPOINT = "https://csc.test"
TOKEN = "Bearer test-token"
DOCUMENT_SIGNING_EKU = x509.ObjectIdentifier("1.3.6.1.5.5.7.3.36")


def _name(cn: str) -> x509.Name:
    return x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SDK Test"),
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        ]
    )


def _make_pki(leaf_cn: str):
    now = datetime.datetime.now(datetime.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root = (
        x509.CertificateBuilder()
        .subject_name(_name("SDK Test Root"))
        .issuer_name(_name("SDK Test Root"))
        .public_key(root_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(root_key.public_key()), critical=False
        )
        .sign(root_key, hashes.SHA256())
    )

    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_name(leaf_cn))
        .issuer_name(root.subject)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([DOCUMENT_SIGNING_EKU, ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(root_key.public_key()),
            critical=False,
        )
        .sign(root_key, hashes.SHA256())
    )
    return root, leaf, leaf_key


class FakeResponse:
    def __init__(self, status: int, payload: dict):
        self.status_code = status
        self.content = json.dumps(payload).encode()
        self.ok = 200 <= status < 300

    def json(self):
        return json.loads(self.content)


class FakeCscSession:
    """Stands in for ``requests.Session``: answers CSC v0 calls by signing
    with local keys. ``credentials`` maps credential IDs to
    ``(chain_der, private_key)``."""

    def __init__(self, credentials):
        self.credentials = credentials
        self.calls = []

    def post(self, url, headers=None, data=None, timeout=None):
        path = url[len(CSC_ENDPOINT):]
        body = json.loads(data)
        self.calls.append((path, body))
        if headers.get("Authorization") != TOKEN:
            return FakeResponse(401, {"error": "invalid_token"})

        cred = self.credentials.get(body.get("credentialID"))
        if cred is None:
            return FakeResponse(400, {"error": "invalid_request", "error_description": "unknown credential"})
        chain, key = cred

        if path == "/csc/v0/credentials/info":
            return FakeResponse(
                200,
                {
                    "cert": {"certificates": [base64.b64encode(c).decode() for c in chain]},
                    "key": {"algo": ["1.2.840.10045.4.3.2"]},
                },
            )
        if path == "/csc/v0/credentials/authorize":
            return FakeResponse(200, {"SAD": "sad-token"})
        if path == "/csc/v0/signatures/signHash":
            sigs = [
                base64.b64encode(
                    key.sign(base64.b64decode(h), ec.ECDSA(utils.Prehashed(hashes.SHA256())))
                ).decode()
                for h in body["hash"]
            ]
            return FakeResponse(200, {"signatures": sigs})
        return FakeResponse(404, {"error": "not found"})

    def get(self, *args, **kwargs):
        raise AssertionError("unexpected GET; the SDK should not download anything")


@pytest.fixture(scope="session")
def pki():
    claim_root, claim_leaf, claim_key = _make_pki("SDK Test Claim Signer")
    id_root, id_leaf, id_key = _make_pki("SDK Test Identity")
    der = lambda c: c.public_bytes(serialization.Encoding.DER)  # noqa: E731
    pem = lambda c: c.public_bytes(serialization.Encoding.PEM).decode()  # noqa: E731
    return {
        "credentials": {
            "claim-cred": ([der(claim_leaf), der(claim_root)], claim_key),
            "identity-cred": ([der(id_leaf), der(id_root)], id_key),
        },
        "anchors": pem(claim_root) + pem(id_root),
    }


@pytest.fixture()
def csc(pki):
    return FakeCscSession(pki["credentials"])


def _png_chunk(kind: bytes, data: bytes) -> bytes:
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


@pytest.fixture(scope="session")
def png_bytes() -> bytes:
    width = height = 16
    raw = b"".join(
        b"\x00" + b"".join(bytes([x * 16, y * 16, 128]) for x in range(width))
        for y in range(height)
    )
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(raw))
        + _png_chunk(b"IEND", b"")
    )


@pytest.fixture(scope="session")
def pdf_bytes() -> bytes:
    # The PDF flow excludes the first len(placeholder) bytes of the source from
    # the data hash (as the Provenance API does), so the document must be larger
    # than the placeholder manifest (tens of KB).
    content = b"BT /F1 12 Tf 20 100 Td (SDK test) Tj ET\n" * 2000
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
    ]
    out = bytearray(b"%PDF-1.4\n")
    offsets = []
    for i, obj in enumerate(objects, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + obj + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objects) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objects) + 1,
        xref,
    )
    return bytes(out)
