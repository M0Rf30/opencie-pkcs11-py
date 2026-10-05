# SPDX-License-Identifier: MPL-2.0

"""Pythonic wrappers around the CIE extensions exported by libopencie-pkcs11."""

from __future__ import annotations

import ctypes
from collections.abc import Callable
from ctypes import (
    POINTER,
    byref,
    c_char,
    c_int,
    c_size_t,
    c_ubyte,
    c_uint16,
    c_ulong,
)
from dataclasses import dataclass

from opencie_pkcs11._ffi import (
    CIE_ERR_CARD_COMMUNICATION,
    CIE_ERR_FILE_NOT_FOUND,
    CIE_ERR_INS_NOT_SUPPORTED,
    CIE_ERR_NONE,
    CIE_ERR_PIN_BLOCKED,
    CIE_ERR_PIN_NOT_SET,
    CIE_ERR_SECURITY_NOT_SATISFIED,
    CIE_ERR_UNKNOWN,
    CIE_ERR_UNSUPPORTED_CARD,
    CIE_ERR_WRONG_CAN,
    CIE_ERR_WRONG_PARAMS,
    CIE_ERR_WRONG_PIN,
    CKR_BUFFER_TOO_SMALL,
    CKR_OK,
    CKR_PIN_INCORRECT,
    COMPLETED_CALLBACK,
    PROGRESS_CALLBACK,
    SIGN_COMPLETED_CALLBACK,
    VerifyInfoC,
    lib,
)
from opencie_pkcs11.pkcs11 import PKCS11Error

# Threshold separating "small positive count" from "PKCS#11 error code" in
# the return value of cie_get_sign_count(). cie_verify() is checked more
# strictly: its result must equal cie_get_sign_count().
RV_COUNT_LIMIT = 0x1000

#: Callback invoked with ``(percentage, message)`` while an operation runs.
ProgressCallback = Callable[[int, str], None]
#: Callback invoked with ``(pan, name, serial)`` when an enrolment completes.
EnrolCompletedCallback = Callable[[str, str, str], None]
#: Callback invoked with the result code (0 = success) when signing completes.
SignCompletedCallback = Callable[[int], None]

_KNOWN_ERROR_KINDS = frozenset(
    {
        CIE_ERR_NONE,
        CIE_ERR_WRONG_PIN,
        CIE_ERR_PIN_BLOCKED,
        CIE_ERR_PIN_NOT_SET,
        CIE_ERR_SECURITY_NOT_SATISFIED,
        CIE_ERR_FILE_NOT_FOUND,
        CIE_ERR_WRONG_PARAMS,
        CIE_ERR_INS_NOT_SUPPORTED,
        CIE_ERR_CARD_COMMUNICATION,
        CIE_ERR_UNKNOWN,
        CIE_ERR_UNSUPPORTED_CARD,
        CIE_ERR_WRONG_CAN,
    }
)


class CieError(PKCS11Error):
    """A CK_RV failure enriched with the library's classified error kind.

    ``kind`` is one of the ``CIE_ERR_*`` constants and ``sw`` the raw ISO 7816
    status word (both as reported by ``cie_last_error()`` right after the
    failing call).
    """

    def __init__(self, rv: int, kind: int, sw: int) -> None:
        super().__init__(rv)
        self.kind = kind
        self.sw = sw
        self.args = (f"CKR 0x{rv:08X} (CIE error kind {kind}, SW 0x{sw:04X})",)


class WrongCanError(CieError):
    """The 6-digit CAN was rejected by PACE (CKR_PIN_INCORRECT + CIE_ERR_WRONG_CAN).

    The library never retries a wrong CAN automatically; neither should callers.
    """


def _check_rv(rv: int) -> None:
    if rv != CKR_OK:
        raise PKCS11Error(rv)


def _check_rv_attempts(rv: int, attempts: c_int) -> None:
    """Like _check_rv, exposing the remaining attempts on the exception."""
    if rv != CKR_OK:
        err = PKCS11Error(rv)
        err.attempts = attempts.value
        raise err


def _raise_classified(rv: int) -> None:
    """Raise the most specific exception for a failed data-group read."""
    try:
        kind, sw = last_error()
    except AttributeError:
        raise PKCS11Error(rv) from None
    if kind == CIE_ERR_WRONG_CAN and rv == CKR_PIN_INCORRECT:
        raise WrongCanError(rv, kind, sw)
    if kind != CIE_ERR_NONE:
        raise CieError(rv, kind, sw)
    raise PKCS11Error(rv)


def _rv_count(rv: int) -> int:
    if rv >= RV_COUNT_LIMIT:
        raise PKCS11Error(rv)
    return int(rv)


def _fixed_to_str(buf: bytes) -> str:
    return buf.split(b"\x00", 1)[0].decode(errors="replace")


def _decode(raw: bytes | None) -> str:
    return raw.decode(errors="replace") if raw else ""


class _Callbacks:
    """Native callbacks handed to the library for the duration of one call.

    libopencie-pkcs11 invokes every callback unconditionally, so NULL must
    never be passed. Exceptions cannot propagate through C frames; the first
    one is stored and re-raised by :meth:`raise_deferred` once the call
    returned. The instance keeps the ctypes thunks alive.
    """

    def __init__(
        self,
        progress: ProgressCallback | None = None,
        completed: EnrolCompletedCallback | None = None,
        sign_completed: SignCompletedCallback | None = None,
    ) -> None:
        self._error: BaseException | None = None

        def on_progress(pct: int, msg: bytes | None) -> int:
            if progress is not None and self._error is None:
                try:
                    progress(int(pct), _decode(msg))
                except BaseException as exc:
                    self._error = exc
            return CKR_OK

        def on_completed(
            pan: bytes | None, name: bytes | None, serial: bytes | None
        ) -> int:
            if completed is not None and self._error is None:
                try:
                    completed(_decode(pan), _decode(name), _decode(serial))
                except BaseException as exc:
                    self._error = exc
            return CKR_OK

        def on_sign_completed(ret: int) -> int:
            if sign_completed is not None and self._error is None:
                try:
                    sign_completed(int(ret))
                except BaseException as exc:
                    self._error = exc
            return CKR_OK

        self.progress = PROGRESS_CALLBACK(on_progress)
        self.completed = COMPLETED_CALLBACK(on_completed)
        self.sign_completed = SIGN_COMPLETED_CALLBACK(on_sign_completed)

    def raise_deferred(self) -> None:
        if self._error is not None:
            err, self._error = self._error, None
            raise err


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


def enable(
    pan: str,
    pin: str,
    progress: ProgressCallback | None = None,
    completed: EnrolCompletedCallback | None = None,
) -> int:
    """Enrol a CIE card identified by PAN using the 8-digit PIN.

    Returns the remaining PIN attempts (as reported by the library). On
    failure raises PKCS11Error whose ``attempts`` attribute holds the
    remaining PIN attempts. ``progress(percentage, message)`` and
    ``completed(pan, name, serial)`` are optional notifications.
    """
    attempts = c_int(0)
    cbs = _Callbacks(progress=progress, completed=completed)
    rv = lib.cie_enable(
        pan.encode(), pin.encode(), byref(attempts), cbs.progress, cbs.completed
    )
    cbs.raise_deferred()
    _check_rv_attempts(rv, attempts)
    return attempts.value


def is_enabled(pan: str) -> bool:
    """Return True if the card identified by PAN is currently enrolled.

    Since libopencie-pkcs11 1.3.0 this returns True only if a pairing cache
    (~/.CIEPKI) exists for that PAN; a card that is merely inserted is not
    reported as enrolled.
    """
    return lib.cie_is_enabled(pan.encode()) == 1


def disable(pan: str) -> None:
    """Remove the enrolment for the card identified by PAN.

    Raises PKCS11Error(CKR_FUNCTION_FAILED) if the card was not enrolled.
    """
    _check_rv(lib.cie_disable(pan.encode()))


def change_pin(
    current_pin: str, new_pin: str, progress: ProgressCallback | None = None
) -> int:
    """Change the PIN. Returns the remaining attempts.

    On failure raises PKCS11Error whose ``attempts`` attribute holds the
    remaining attempts.
    """
    attempts = c_int(0)
    cbs = _Callbacks(progress=progress)
    rv = lib.cie_change_pin(
        current_pin.encode(), new_pin.encode(), byref(attempts), cbs.progress
    )
    cbs.raise_deferred()
    _check_rv_attempts(rv, attempts)
    return attempts.value


def unblock_pin(
    puk: str, new_pin: str, progress: ProgressCallback | None = None
) -> int:
    """Unblock the PIN using the PUK and set a new PIN. Returns remaining attempts.

    On failure raises PKCS11Error whose ``attempts`` attribute holds the
    remaining PUK attempts.
    """
    attempts = c_int(0)
    cbs = _Callbacks(progress=progress)
    rv = lib.cie_unblock_pin(
        puk.encode(), new_pin.encode(), byref(attempts), cbs.progress
    )
    cbs.raise_deferred()
    _check_rv_attempts(rv, attempts)
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
    progress: ProgressCallback | None = None,
    completed: SignCompletedCallback | None = None,
) -> None:
    """Sign a PDF on behalf of the card identified by pan.

    sig_type is the signature type string ("PDF", "P7M", ...). page is the
    0-based page index for the signature widget. x, y, w, h are fractions
    (0.0-1.0) of the page crop box: x/y are the left/bottom position and
    w/h the width/height; w == 0 or h == 0 hides the visible widget.
    image_data is the optional PNG bytes of the signature stamp.
    ``progress(percentage, message)`` and ``completed(result_code)`` are
    optional notifications.
    """
    if image_data:
        img_buf = (c_ubyte * len(image_data)).from_buffer_copy(image_data)
        img_ptr = ctypes.cast(img_buf, POINTER(c_ubyte))
        img_len = len(image_data)
    else:
        img_ptr = None
        img_len = 0

    cbs = _Callbacks(progress=progress, sign_completed=completed)
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
        cbs.progress,
        cbs.sign_completed,
    )
    cbs.raise_deferred()
    _check_rv(rv)


def verify(
    in_file: str,
    proxy_addr: str | None = None,
    proxy_port: int = 0,
    usr_pass: str | None = None,
) -> int:
    """Verify a signed document. Returns the number of signatures found.

    The library returns the signature count (0 if the file has none) or an
    error code (a CIE_SIGN_ERROR_* value, 0x84000000 and up, or a negative
    status cast to CK_RV). A return value that differs from
    cie_get_sign_count() is an error and raises PKCS11Error. Use
    get_verify_info() to inspect each signature's validity.
    """
    rv = lib.cie_verify(
        in_file.encode(),
        proxy_addr.encode() if proxy_addr else None,
        proxy_port,
        usr_pass.encode() if usr_pass else None,
    )
    if rv != lib.cie_get_sign_count():
        raise PKCS11Error(rv)
    return int(rv)


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


def _free_native(ptr: ctypes.c_void_p) -> None:
    """Release a buffer allocated by the library (cie_free, not libc free)."""
    try:
        free = lib.cie_free
    except AttributeError:
        # Libraries older than 1.3.0 do not export cie_free; their buffers
        # come from the C runtime's malloc.
        libc = ctypes.CDLL(None)
        libc.free.argtypes = [ctypes.c_void_p]
        libc.free.restype = None
        free = libc.free
    free(ptr)


def get_certificate(pan: str) -> bytes:
    """Fetch the DER-encoded auth certificate for the card identified by pan.

    Reads the cache written by enable(). If there is none and the card is on
    a reader, the certificate is taken from the CIE ID pairing cache
    (~/.CIEPKI/<PAN>.cache), which needs the card present to decrypt, and
    cached for later calls. An unpaired card fails (no certificate is
    released without a verified PIN). The native buffer is released with
    cie_free() before returning.
    """
    out_ptr = POINTER(c_ubyte)()
    out_len = c_ulong(0)
    rv = lib.cie_get_certificate(pan.encode(), byref(out_ptr), byref(out_len))
    _check_rv(rv)
    if not out_ptr:
        return b""
    try:
        return ctypes.string_at(out_ptr, out_len.value)
    finally:
        _free_native(ctypes.cast(out_ptr, ctypes.c_void_p))


def timestamp(
    in_file: str,
    tsa_url: str,
    tsa_username: str | None = None,
    tsa_password: str | None = None,
    out_token_path: str = "",
    progress: ProgressCallback | None = None,
) -> None:
    """Request an RFC 3161 timestamp token for in_file, written to out_token_path."""
    cbs = _Callbacks(progress=progress)
    rv = lib.cie_timestamp(
        in_file.encode(),
        tsa_url.encode(),
        tsa_username.encode() if tsa_username else None,
        tsa_password.encode() if tsa_password else None,
        out_token_path.encode(),
        cbs.progress,
    )
    cbs.raise_deferred()
    _check_rv(rv)


_MRZ_BUF_LEN = 4096
_PHOTO_BUF_LEN = 524288


def _read_dgs_call(fn, secret: str) -> tuple[bytes, bytes]:
    mrz_buf = (c_char * _MRZ_BUF_LEN)()
    mrz_len = c_size_t(_MRZ_BUF_LEN)
    photo_buf = (c_ubyte * _PHOTO_BUF_LEN)()
    photo_len = c_size_t(_PHOTO_BUF_LEN)

    rv = fn(
        secret.encode(),
        mrz_buf,
        byref(mrz_len),
        photo_buf,
        byref(photo_len),
    )
    if rv != CKR_OK:
        _raise_classified(rv)
    return ctypes.string_at(mrz_buf, mrz_len.value), ctypes.string_at(
        photo_buf, photo_len.value
    )


def read_dgs_can(can: str) -> tuple[bytes, bytes]:
    """Read DG1 (MRZ) and DG2 (photo) over ICAO 9303 PACE with the 6-digit CAN.

    Returns ``(mrz, photo_png)``: the raw DG1 TLV bytes and the portrait as
    PNG. No PIN is used or consumed. Requires libopencie-pkcs11 >= 1.3.0.

    Failures (all PKCS11Error subclasses carrying ``kind`` and ``sw``):

    - wrong CAN: :class:`WrongCanError` (CKR_PIN_INCORRECT, CIE_ERR_WRONG_CAN);
      never retry automatically with the same CAN;
    - chip without PACE: CKR_FUNCTION_NOT_SUPPORTED with
      CIE_ERR_UNSUPPORTED_CARD;
    - reader without extended-length APDUs: CKR_DEVICE_ERROR with
      CIE_ERR_INS_NOT_SUPPORTED; fall back to :func:`read_dgs` (PIN) or use
      another reader;
    - a CAN that is not exactly 6 ASCII digits: CKR_ARGUMENTS_BAD.
    """
    return _read_dgs_call(lib.cie_read_dgs_can, can)


def read_dgs(pin: str) -> tuple[bytes, bytes]:
    """Read the MRZ and photo data groups with the 8-digit PIN (fallback).

    Returns ``(mrz, photo_png)``. Prefer :func:`read_dgs_can`; use this for
    readers that cannot send the extended-length APDUs PACE needs.
    """
    return _read_dgs_call(lib.cie_read_dgs, pin)


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

    raise PKCS11Error(CKR_BUFFER_TOO_SMALL)


def classify_sw(sw: int) -> int:
    """Classify an ISO 7816 status word to an error kind.

    Args:
        sw: ISO 7816 status word (16-bit value).

    Returns:
        A CIE_ERR_* constant indicating the error classification.
        Unknown status words map to CIE_ERR_UNKNOWN.

    Raises:
        AttributeError: If cie_classify_sw is not available in
            libopencie-pkcs11 (requires a version with error classification
            support).
    """
    try:
        result = lib.cie_classify_sw(sw)
    except AttributeError:
        raise AttributeError(
            "cie_classify_sw not available - requires libopencie-pkcs11 "
            "with error classification support"
        ) from None
    # Map unexpected out-of-range returns to UNKNOWN
    return result if result in _KNOWN_ERROR_KINDS else CIE_ERR_UNKNOWN


def last_error() -> tuple[int, int]:
    """Retrieve the most recent error information on the current thread.

    Returns:
        A tuple of (error_kind, status_word) where:
        - error_kind is a CIE_ERR_* constant, or CIE_ERR_NONE if no error
        - status_word is the raw ISO 7816 status word (0 if not applicable)

    Raises:
        AttributeError: If cie_last_error is not available in
            libopencie-pkcs11 (requires a version with error classification
            support).
    """
    try:
        error_kind = c_int()
        status_word = c_uint16()
        rv = lib.cie_last_error(byref(error_kind), byref(status_word))
        _check_rv(rv)
        return (error_kind.value, status_word.value)
    except AttributeError:
        raise AttributeError(
            "cie_last_error not available - requires libopencie-pkcs11 "
            "with error classification support"
        ) from None
