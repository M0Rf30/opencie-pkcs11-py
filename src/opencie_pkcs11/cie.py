# SPDX-License-Identifier: MPL-2.0

"""Pythonic wrappers around the CIE extensions exported by libopencie-pkcs11."""

from __future__ import annotations

import ctypes
from ctypes import (
    POINTER,
    byref,
    c_char,
    c_int,
    c_size_t,
    c_ubyte,
    c_ulong,
)
from dataclasses import dataclass

from opencie_pkcs11._ffi import VerifyInfoC, lib
from opencie_pkcs11.pkcs11 import PKCS11Error

# Threshold separating "small positive count" from "PKCS#11 error code" in
# the overloaded return values of cie_verify/cie_get_sign_count.
RV_COUNT_LIMIT = 0x1000

_libc = ctypes.CDLL(None)  # default C library
_libc.free.argtypes = [ctypes.c_void_p]
_libc.free.restype = None


def _check_rv(rv: int) -> None:
    if rv != 0:
        raise PKCS11Error(rv)


def _rv_count(rv: int) -> int:
    if rv >= RV_COUNT_LIMIT:
        raise PKCS11Error(rv)
    return int(rv)


def _fixed_to_str(buf: bytes) -> str:
    return buf.split(b"\x00", 1)[0].decode(errors="replace")


@dataclass
class VerifyInfo:
    """Per-signature verification info. Mirrors verifyInfo_t from cie_ext.h."""

    name: str
    surname: str
    cn: str
    signing_time: str
    cadn: str
    cert_revoc_status: int
    is_sign_valid: bool
    is_cert_valid: bool


def enable(pan: str, pin: str) -> int:
    """Enrol a CIE card identified by PAN using the 8-digit PIN.

    Returns remaining PIN attempts on error; raises PKCS11Error on failure.
    Progress/completion callbacks are not exposed; NULL is passed.
    """
    attempts = c_int(0)
    rv = lib.cie_enable(pan.encode(), pin.encode(), byref(attempts), None, None)
    _check_rv(rv)
    return attempts.value


def is_enabled(pan: str) -> bool:
    """Return True if the card identified by PAN is currently enrolled."""
    return lib.cie_is_enabled(pan.encode()) == 1


def disable(pan: str) -> None:
    """Remove the enrolment for the card identified by PAN."""
    _check_rv(lib.cie_disable(pan.encode()))


def change_pin(current_pin: str, new_pin: str) -> int:
    """Change the PIN. Returns remaining attempts on error."""
    attempts = c_int(0)
    rv = lib.cie_change_pin(
        current_pin.encode(), new_pin.encode(), byref(attempts), None
    )
    _check_rv(rv)
    return attempts.value


def unblock_pin(puk: str, new_pin: str) -> int:
    """Unblock the PIN using the PUK and set a new PIN. Returns remaining attempts."""
    attempts = c_int(0)
    rv = lib.cie_unblock_pin(puk.encode(), new_pin.encode(), byref(attempts), None)
    _check_rv(rv)
    return attempts.value


def sign(
    in_file: str,
    sig_type: str,
    pin: str,
    pan: str,
    page: int,
    x: float,
    y: float,
    w: float,
    h: float,
    image_data: bytes | None,
    out_file: str,
) -> None:
    """Sign a PDF on behalf of the card identified by pan.

    sig_type is the signature type string ("PDF", "P7M", ...). page is the
    0-based page index for the signature widget; x, y, w, h define the
    widget position and size in PDF points. image_data is the optional raw
    bytes of a signature stamp image.
    """
    if image_data:
        img_buf = (c_ubyte * len(image_data)).from_buffer_copy(image_data)
        img_ptr = ctypes.cast(img_buf, POINTER(c_ubyte))
        img_len = len(image_data)
    else:
        img_ptr = None
        img_len = 0

    rv = lib.cie_sign(
        in_file.encode(),
        sig_type.encode(),
        pin.encode(),
        pan.encode(),
        page,
        x,
        y,
        w,
        h,
        img_ptr,
        img_len,
        out_file.encode(),
        None,
        None,
    )
    _check_rv(rv)


def verify(
    in_file: str,
    proxy_addr: str | None = None,
    proxy_port: int = 0,
    usr_pass: str | None = None,
) -> int:
    """Verify a signed document. Returns the number of valid signatures found."""
    rv = lib.cie_verify(
        in_file.encode(),
        proxy_addr.encode() if proxy_addr else None,
        proxy_port,
        usr_pass.encode() if usr_pass else None,
    )
    return _rv_count(rv)


def get_sign_count() -> int:
    """Number of signatures found by the last verify() call."""
    return _rv_count(lib.cie_get_sign_count())


def get_verify_info(index: int) -> VerifyInfo:
    """Retrieve signer info for the n-th signature found by the last verify()."""
    info = VerifyInfoC()
    _check_rv(lib.cie_get_verify_info(index, byref(info)))
    return VerifyInfo(
        name=_fixed_to_str(info.name),
        surname=_fixed_to_str(info.surname),
        cn=_fixed_to_str(info.cn),
        signing_time=_fixed_to_str(info.signingTime),
        cadn=_fixed_to_str(info.cadn),
        cert_revoc_status=info.CertRevocStatus,
        is_sign_valid=info.isSignValid != 0,
        is_cert_valid=info.isCertValid != 0,
    )


def extract_p7m(in_file: str, out_file: str) -> None:
    """Extract the original (unwrapped) document from a .p7m envelope."""
    _check_rv(lib.cie_extract_p7m(in_file.encode(), out_file.encode()))


def reader_count() -> int:
    """Number of currently attached PC/SC readers."""
    return lib.cie_reader_count()


def reader_watch(current_count: int) -> int:
    """Block until the reader count changes from current_count; return the new count."""
    return lib.cie_reader_watch(current_count)


def reader_name() -> str | None:
    """Name of the first attached reader, or None if no reader is attached."""
    buf_len = 256
    buf = ctypes.create_string_buffer(buf_len)
    n = lib.cie_reader_name(buf, buf_len)
    if n <= 0:
        return None
    return buf.raw[: min(n, buf_len)].split(b"\x00", 1)[0].decode(errors="replace")


def get_certificate(pan: str) -> bytes:
    """Fetch the DER-encoded auth certificate for the card identified by pan."""
    out_ptr = POINTER(c_ubyte)()
    out_len = c_ulong(0)
    rv = lib.cie_get_certificate(pan.encode(), byref(out_ptr), byref(out_len))
    _check_rv(rv)
    try:
        return ctypes.string_at(out_ptr, out_len.value)
    finally:
        _libc.free(ctypes.cast(out_ptr, ctypes.c_void_p))


def timestamp(
    in_file: str,
    tsa_url: str,
    tsa_username: str | None = None,
    tsa_password: str | None = None,
    out_token_path: str = "",
) -> None:
    """Request an RFC 3161 timestamp token for in_file, written to out_token_path."""
    rv = lib.cie_timestamp(
        in_file.encode(),
        tsa_url.encode(),
        tsa_username.encode() if tsa_username else None,
        tsa_password.encode() if tsa_password else None,
        out_token_path.encode(),
        None,
    )
    _check_rv(rv)


def read_dgs(pin: str) -> tuple[bytes, bytes]:
    """Read the MRZ and photo data groups from the card. Returns (mrz, photo_png)."""
    mrz_buf = (c_char * 4096)()
    mrz_len = c_size_t(4096)
    photo_buf = (c_ubyte * 524288)()
    photo_len = c_size_t(524288)

    rv = lib.cie_read_dgs(
        pin.encode(),
        mrz_buf,
        byref(mrz_len),
        photo_buf,
        byref(photo_len),
    )
    _check_rv(rv)
    return ctypes.string_at(mrz_buf, mrz_len.value), ctypes.string_at(
        photo_buf, photo_len.value
    )


def make_digest_info(algid: int, digest: bytes) -> bytes:
    """Build a DER-encoded PKCS#1 DigestInfo from a raw digest value.

    algid is the OpenSSL NID of the digest algorithm:
    SHA-1=65, SHA-256=672, SHA-384=673, SHA-512=674.
    """
    if not digest:
        raise ValueError("digest is empty")

    buf_len = c_size_t(256)
    for _ in range(4):
        out = (c_ubyte * buf_len.value)()
        digest_buf = (c_ubyte * len(digest)).from_buffer_copy(digest)
        ok = lib.make_digest_info(
            algid,
            digest_buf,
            len(digest),
            out,
            byref(buf_len),
        )
        if ok == 1:
            return ctypes.string_at(out, buf_len.value)
        buf_len.value = (
            buf_len.value * 2 if buf_len.value < 1024 else buf_len.value + 512
        )

    raise PKCS11Error(0x150)  # CKR_BUFFER_TOO_SMALL
