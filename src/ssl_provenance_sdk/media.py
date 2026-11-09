"""Supported media types and per-format asset preparation."""

from __future__ import annotations

import struct

#: MIME types supported by c2pa for embedding manifests.
SUPPORTED_MIME_TYPES = (
    # Images
    "image/jpeg",
    "image/png",
    "image/gif",
    "image/tiff",
    "image/webp",
    "image/avif",
    "image/heic",
    "image/heif",
    "image/svg+xml",
    "image/dng",
    "image/x-adobe-dng",
    "image/x-sony-arw",
    "image/x-nikon-nef",
    "image/jxl",
    # Video
    "video/mp4",
    "video/quicktime",
    "video/x-m4v",
    "video/avi",
    "video/msvideo",
    "video/x-msvideo",
    # Audio
    "audio/mpeg",
    "audio/mp4",
    "audio/flac",
    "audio/wav",
    "audio/wave",
    "audio/x-wav",
    "audio/vnd.wave",
    # Documents / manifests / XML
    "application/pdf",
    "application/mp4",
    "application/c2pa",
    "application/x-c2pa-manifest-store",
    "application/x-troff-msvideo",
    "application/svg+xml",
    "application/xhtml+xml",
    "application/xml",
    "text/xml",
)

PDF_MIME_TYPE = "application/pdf"

#: Content type of the sidecar manifest returned for PDF assets.
SIDECAR_MIME_TYPE = "application/c2pa"


def normalize_content_type(content_type: str | None) -> str:
    """Strip any parameters (e.g. ``"; charset=utf-8"``) and surrounding whitespace."""
    return (content_type or "").split(";", 1)[0].strip()


def is_supported(content_type: str) -> bool:
    return content_type in SUPPORTED_MIME_TYPES


def c2pa_format(mime: str) -> str:
    """Map MIME types that share the MP4/ISOBMFF container to the format c2pa recognises."""
    if mime == "audio/mp4":
        return "video/mp4"
    return mime


#: The 12-byte ISOBMFF signature box that begins every JPEG XL *container*.
JXL_CONTAINER_SIG = bytes(
    [0x00, 0x00, 0x00, 0x0C, 0x4A, 0x58, 0x4C, 0x20, 0x0D, 0x0A, 0x87, 0x0A]
)

_JXL_CODESTREAM_MAGIC = b"\xff\x0a"

#: File-type box: size=20, 'ftyp', major brand 'jxl ', minor version 0, one
#: compatible brand 'jxl '.
_JXL_FTYP_BOX = b"\x00\x00\x00\x14ftypjxl \x00\x00\x00\x00jxl "


def wrap_jxl_codestream(data: bytes) -> bytes:
    """Wrap a bare JPEG XL *codestream* (magic ``FF 0A``) into a minimal ISOBMFF
    *container* so a C2PA manifest can be embedded.

    JPEG XL ships in two forms: a raw codestream and the ISOBMFF container
    (``....JXL␠``). c2pa can only embed a manifest into the container form, so a
    codestream is losslessly wrapped here as ``signature + ftyp + jxlc`` boxes
    (the original codestream bytes sit verbatim inside the ``jxlc`` box — no
    re-encode). Input that is already a container, or is not a recognised JXL
    codestream, is returned unchanged.
    """
    if data.startswith(JXL_CONTAINER_SIG) or not data.startswith(_JXL_CODESTREAM_MAGIC):
        return data

    payload = len(data)
    box_len = 8 + payload
    if box_len <= 0xFFFFFFFF:
        jxlc_header = struct.pack(">I", box_len) + b"jxlc"
    else:
        # 64-bit "large size": 4-byte size field = 1, then 8-byte actual length
        # (which includes the 16-byte box header).
        jxlc_header = struct.pack(">I", 1) + b"jxlc" + struct.pack(">Q", 16 + payload)

    return JXL_CONTAINER_SIG + _JXL_FTYP_BOX + jxlc_header + data
