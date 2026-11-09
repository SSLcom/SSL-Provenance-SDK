"""COSE_Sign1 construction for the CAWG X.509 identity assertion.

c2pa's ``X509CredentialHolder`` signs the CAWG ``signer_payload`` as a detached
COSE_Sign1 with an RFC 3161 ``sigTst2`` countersignature timestamp. The native
library's X.509 identity entry point drops the identity signer's TSA, so the SDK
hands c2pa a credential-holder callback instead and assembles the same
structure here:

* protected header: ``alg`` and ``x5chain`` (RFC 9360)
* signature over ``Sig_structure("Signature1", protected, h'', payload)``
* unprotected header: ``sigTst2`` = ``{"tstTokens": [{"val": TimeStampToken}]}``
  timestamping ``Sig_structure("CounterSignature", protected, h'', bstr(sig))``
* payload detached (``nil``), CBOR tag 18
"""

from __future__ import annotations

from typing import Callable, Optional, Sequence

import cbor2
from asn1crypto import algos, x509

COSE_SIGN1_TAG = 18
_HEADER_ALG = 1
_HEADER_X5CHAIN = 33

#: COSE algorithm identifiers (RFC 9053 / RFC 8230) keyed by c2pa alg name.
COSE_ALGORITHMS = {
    "es256": -7,
    "es384": -35,
    "es512": -36,
    "ps256": -37,
    "ps384": -38,
    "ps512": -39,
    "ed25519": -8,
}

#: P1363 (raw ``r || s``) component length per named curve.
_CURVE_COMPONENT_LEN = {
    "secp256r1": 32,
    "secp384r1": 48,
    "secp521r1": 66,
}

_ALG_COMPONENT_LEN = {"es256": 32, "es384": 48, "es512": 66}


def protected_header(alg: str, cert_chain: Sequence[bytes]) -> bytes:
    """Serialized protected header: ``alg`` then ``x5chain``.

    A single certificate is a byte string; a chain is an array of them.
    """
    if alg not in COSE_ALGORITHMS:
        raise ValueError(f"unsupported COSE signing algorithm: {alg}")
    chain = list(cert_chain)
    x5chain = chain[0] if len(chain) == 1 else chain
    return cbor2.dumps({_HEADER_ALG: COSE_ALGORITHMS[alg], _HEADER_X5CHAIN: x5chain})


def sig_structure(context: str, protected: bytes, payload: bytes) -> bytes:
    """``Sig_structure`` (RFC 9052 §4.4) with empty external AAD."""
    return cbor2.dumps([context, protected, b"", payload])


def to_p1363(signature: bytes, alg: str, signing_cert: Optional[bytes]) -> bytes:
    """Convert a DER ``ECDSA-Sig-Value`` to the raw ``r || s`` form COSE needs.

    Signatures that are not DER (already raw), and non-EC algorithms, are
    returned unchanged. The component length comes from the signing
    certificate's curve, falling back to the algorithm.
    """
    if alg not in _ALG_COMPONENT_LEN:
        return signature
    try:
        parsed = algos.DSASignature.load(signature, strict=True)
        r = parsed["r"].native
        s = parsed["s"].native
    except (ValueError, TypeError):
        return signature

    size = _ALG_COMPONENT_LEN[alg]
    if signing_cert is not None:
        try:
            cert = x509.Certificate.load(signing_cert)
            curve = cert.public_key["algorithm"]["parameters"].chosen.native
            size = _CURVE_COMPONENT_LEN.get(curve, size)
        except (ValueError, TypeError, KeyError, AttributeError):
            pass

    return r.to_bytes(size, "big") + s.to_bytes(size, "big")


def sign1_detached(
    payload: bytes,
    alg: str,
    cert_chain: Sequence[bytes],
    sign: Callable[[bytes], bytes],
    time_stamp: Optional[Callable[[bytes], bytes]] = None,
) -> bytes:
    """Produce a tagged, detached-payload COSE_Sign1 over ``payload``.

    Args:
        payload: The bytes to sign (for CAWG, the CBOR ``signer_payload``).
        alg: c2pa algorithm name (``es256``, ``ps256``, ...).
        cert_chain: DER certificates, end-entity first.
        sign: Raw signer: returns the signature over the bytes it is given.
        time_stamp: Returns a DER ``TimeStampToken`` for the bytes it is given,
            or ``None`` to omit ``sigTst2``.
    """
    protected = protected_header(alg, cert_chain)

    signature = sign(sig_structure("Signature1", protected, payload))
    signature = to_p1363(signature, alg, cert_chain[0] if cert_chain else None)

    unprotected: dict = {}
    if time_stamp is not None:
        countersign_data = sig_structure(
            "CounterSignature", protected, cbor2.dumps(signature)
        )
        token = time_stamp(countersign_data)
        unprotected["sigTst2"] = {"tstTokens": [{"val": token}]}

    return cbor2.dumps(
        cbor2.CBORTag(COSE_SIGN1_TAG, [protected, unprotected, None, signature])
    )
