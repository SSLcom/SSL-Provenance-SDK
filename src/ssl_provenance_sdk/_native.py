"""Bindings for native c2pa entry points that c2pa-python does not wrap.

c2pa-python loads ``libc2pa_c`` and wraps most of it, but not:

* ``c2pa_identity_signer_create_with_credential_holder`` (CAWG identity
  assertion with a caller-produced signature), and
* ``c2pa_builder_data_hashed_placeholder`` /
  ``c2pa_builder_sign_data_hashed_embeddable`` (the data-hashed embeddable
  workflow used for PDF sidecar manifests).

This module declares those functions on c2pa-python's own library handle and
drives them through its handle-ownership helpers, so native objects stay owned
and freed by the c2pa-python ``Signer``/``Builder`` instances. Those helpers are
private to c2pa-python, which is why ``pyproject.toml`` pins its minor version;
everything that touches them lives in this one module.
"""

from __future__ import annotations

import ctypes
import io
import logging
from typing import Callable, List, Optional, Sequence

import c2pa
from c2pa import c2pa as _c2pa

logger = logging.getLogger(__name__)

_lib = _c2pa._lib
_ubyte_p = ctypes.POINTER(ctypes.c_ubyte)

#: ``CredentialHolderCallback`` — same shape as c2pa's ``SignerCallback``:
#: (context, data, len, signed_bytes, signed_len) -> isize
CredentialHolderCallback = ctypes.CFUNCTYPE(
    ctypes.c_ssize_t,
    ctypes.c_void_p,
    _ubyte_p,
    ctypes.c_size_t,
    _ubyte_p,
    ctypes.c_size_t,
)

_lib.c2pa_identity_signer_create_with_credential_holder.argtypes = [
    ctypes.POINTER(_c2pa.C2paSigner),
    ctypes.c_char_p,
    ctypes.c_size_t,
    ctypes.c_void_p,
    CredentialHolderCallback,
    ctypes.POINTER(ctypes.c_char_p),
    ctypes.POINTER(ctypes.c_char_p),
]
_lib.c2pa_identity_signer_create_with_credential_holder.restype = ctypes.POINTER(
    _c2pa.C2paSigner
)

_lib.c2pa_builder_data_hashed_placeholder.argtypes = [
    ctypes.POINTER(_c2pa.C2paBuilder),
    ctypes.c_size_t,
    ctypes.c_char_p,
    ctypes.POINTER(_ubyte_p),
]
_lib.c2pa_builder_data_hashed_placeholder.restype = ctypes.c_int64

_lib.c2pa_builder_sign_data_hashed_embeddable.argtypes = [
    ctypes.POINTER(_c2pa.C2paBuilder),
    ctypes.POINTER(_c2pa.C2paSigner),
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.POINTER(_c2pa.C2paStream),
    ctypes.POINTER(_ubyte_p),
]
_lib.c2pa_builder_sign_data_hashed_embeddable.restype = ctypes.c_int64


def _cstr_array(values: Sequence[str]):
    """NULL-terminated ``const char*[]``, or NULL when empty."""
    if not values:
        return None
    arr = (ctypes.c_char_p * (len(values) + 1))()
    for i, value in enumerate(values):
        arr[i] = value.encode("utf-8")
    arr[len(values)] = None
    return arr


def _take_bytes(ptr, length: int) -> bytes:
    """Copy and free a native byte buffer."""
    try:
        return ctypes.string_at(ptr, length) if length > 0 else b""
    finally:
        if ptr:
            _lib.c2pa_free(ptr)


def add_credential_holder_identity(
    signer: c2pa.Signer,
    sig_type: str,
    reserve_size: int,
    sign_payload: Callable[[bytes], bytes],
    referenced_assertions: Sequence[str] = (),
    roles: Sequence[str] = (),
) -> None:
    """Make ``signer`` also embed a CAWG identity assertion.

    The native signer behind ``signer`` is consumed and replaced (in place) by
    one that signs the claim exactly as before and adds a ``cawg.identity``
    dynamic assertion whose ``signature`` field is ``sign_payload(payload)``,
    where ``payload`` is the CBOR ``signer_payload``.
    """
    errors: List[BaseException] = []

    def callback(_context, data_ptr, data_len, out_ptr, out_len):
        try:
            payload = ctypes.string_at(data_ptr, data_len)
            signature = sign_payload(payload)
            if len(signature) > out_len:
                raise ValueError(
                    f"identity signature is {len(signature)} bytes, "
                    f"exceeding the {out_len} byte reserve"
                )
            ctypes.memmove(out_ptr, signature, len(signature))
            return len(signature)
        except BaseException as e:  # noqa: BLE001 - must not unwind into native code
            logger.error("CAWG identity signing failed: %s", e)
            errors.append(e)
            return -1

    callback_cb = CredentialHolderCallback(callback)
    refs = _cstr_array(referenced_assertions)
    role_arr = _cstr_array(roles)

    signer._consume_and_swap(
        lambda handle: _lib.c2pa_identity_signer_create_with_credential_holder(
            handle,
            sig_type.encode("utf-8"),
            reserve_size,
            None,
            callback_cb,
            refs,
            role_arr,
        ),
        "Failed to create CAWG identity signer: {}",
    )

    # The native signer calls back into Python for as long as it lives, so the
    # ctypes thunk must live as long as the Signer object.
    holders = getattr(signer, "_ssl_identity_callbacks", [])
    holders.append((callback_cb, errors))
    signer._ssl_identity_callbacks = holders


def identity_callback_errors(signer: c2pa.Signer) -> List[BaseException]:
    """Exceptions raised inside identity callbacks attached to ``signer``."""
    return [
        e for _, errors in getattr(signer, "_ssl_identity_callbacks", []) for e in errors
    ]


def data_hashed_placeholder(builder: c2pa.Builder, reserved_size: int, format: str) -> bytes:
    """Placeholder manifest bytes sized for a signature of ``reserved_size``."""
    builder._ensure_valid_state()
    out = _ubyte_p()
    with builder._exclusive_native_call():
        result = _lib.c2pa_builder_data_hashed_placeholder(
            builder._handle, reserved_size, format.encode("utf-8"), ctypes.byref(out)
        )
    _c2pa._check_ffi_operation_result(
        result, "Failed to create data hashed placeholder", check=lambda r: r < 0
    )
    return _take_bytes(out, result)


def sign_data_hashed_embeddable(
    builder: c2pa.Builder,
    signer: c2pa.Signer,
    data_hash_json: str,
    format: str,
    asset: Optional[bytes],
) -> bytes:
    """Sign the builder against a ``DataHash`` and return the manifest bytes.

    When ``asset`` is given, c2pa computes the data hash over it (honouring the
    ``exclusions`` in ``data_hash_json``); otherwise the JSON must already carry
    the ``hash``.
    """
    builder._ensure_valid_state()
    if not getattr(signer, "_handle", None):
        raise c2pa.C2paError("Invalid or closed signer")

    stream = c2pa.Stream(io.BytesIO(asset)) if asset is not None else None
    out = _ubyte_p()
    try:
        with builder._exclusive_native_call(), signer._native_call():
            result = _lib.c2pa_builder_sign_data_hashed_embeddable(
                builder._handle,
                signer._handle,
                data_hash_json.encode("utf-8"),
                format.encode("utf-8"),
                stream._stream if stream is not None else None,
                ctypes.byref(out),
            )
    finally:
        if stream is not None:
            stream.close()

    _c2pa._check_ffi_operation_result(
        result, "Failed to sign data hashed embeddable manifest", check=lambda r: r < 0
    )
    return _take_bytes(out, result)
