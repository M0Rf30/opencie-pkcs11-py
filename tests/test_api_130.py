# SPDX-License-Identifier: MPL-2.0

"""Contract tests for the libopencie-pkcs11 1.3.0 public API (cie_ext.h).

No smart card is needed: layouts and prototypes are checked statically, and
the behaviour of the wrappers is checked against a fake ``lib`` object.
"""

import ctypes
import sys

import pytest

from opencie_pkcs11 import _ffi, cie
from opencie_pkcs11.pkcs11 import PKCS11Error

# ---------------------------------------------------------------------------
# Layouts, enums and integer widths
# ---------------------------------------------------------------------------


def test_verify_info_layout():
    assert _ffi.OPENCIE_MAX_LEN == 512
    offsets = {
        f: getattr(_ffi.VerifyInfoC, f).offset for f, *_ in _ffi.VerifyInfoC._fields_
    }
    for i, name in enumerate(["name", "surname", "cn", "signingTime", "cadn"]):
        assert offsets[name] == i * 1024
    assert offsets["CertRevocStatus"] == 5 * 1024
    assert offsets["isSignValid"] == 5 * 1024 + 4
    assert offsets["isCertValid"] == 5 * 1024 + 8
    assert ctypes.sizeof(_ffi.VerifyInfoC) == 5 * 1024 + 12


def test_ck_rv_is_unsigned_long():
    assert _ffi.CK_RV is ctypes.c_ulong
    assert ctypes.sizeof(_ffi.CK_RV) == ctypes.sizeof(ctypes.c_ulong)


def test_error_kind_values_130():
    assert _ffi.CIE_ERR_UNSUPPORTED_CARD == 10
    assert _ffi.CIE_ERR_WRONG_CAN == 11


def test_return_code_values():
    assert _ffi.CKR_PIN_INCORRECT == 0xA0
    assert _ffi.CKR_FUNCTION_NOT_SUPPORTED == 0x54
    assert _ffi.CKR_DEVICE_ERROR == 0x30
    assert _ffi.CKR_ARGUMENTS_BAD == 0x07
    assert _ffi.CIE_SIGN_ERROR_BASE == 0x84000000


@pytest.mark.skipif(sys.platform != "win32", reason="Windows packs PKCS#11 structs")
def test_pkcs11_structs_are_packed_on_windows():
    assert _ffi.CK_VERSION._pack_ == 1
    assert _ffi.CK_INFO._pack_ == 1
    assert ctypes.sizeof(_ffi.CK_INFO) == 2 + 32 + 4 + 32 + 2


def test_callback_signatures_return_ck_rv():
    for cb in (
        _ffi.PROGRESS_CALLBACK,
        _ffi.COMPLETED_CALLBACK,
        _ffi.SIGN_COMPLETED_CALLBACK,
    ):
        assert cb._restype_ is _ffi.CK_RV
    assert _ffi.PROGRESS_CALLBACK._argtypes_ == (ctypes.c_int, ctypes.c_char_p)
    assert len(_ffi.COMPLETED_CALLBACK._argtypes_) == 3
    assert _ffi.SIGN_COMPLETED_CALLBACK._argtypes_ == (ctypes.c_int,)


# ---------------------------------------------------------------------------
# Prototypes of the loaded library (skipped on libraries lacking a symbol)
# ---------------------------------------------------------------------------


def test_read_dgs_can_prototype():
    if not hasattr(_ffi.lib, "cie_read_dgs_can"):
        pytest.skip("libopencie-pkcs11 < 1.3.0")
    fn = _ffi.lib.cie_read_dgs_can
    assert fn.restype is _ffi.CK_RV
    assert len(fn.argtypes) == 5
    assert fn.argtypes[2] is not None and fn.argtypes[4] is not None


def test_cie_free_prototype():
    if not hasattr(_ffi.lib, "cie_free"):
        pytest.skip("libopencie-pkcs11 < 1.3.0")
    assert _ffi.lib.cie_free.restype is None
    assert _ffi.lib.cie_free.argtypes == [ctypes.c_void_p]


def test_classify_sw_real_library():
    if not hasattr(_ffi.lib, "cie_classify_sw"):
        pytest.skip("libopencie-pkcs11 lacks cie_classify_sw")
    assert cie.classify_sw(0x63C2) == _ffi.CIE_ERR_WRONG_PIN
    assert cie.classify_sw(0x6983) == _ffi.CIE_ERR_PIN_BLOCKED
    assert cie.classify_sw(0x6D00) == _ffi.CIE_ERR_INS_NOT_SUPPORTED


# ---------------------------------------------------------------------------
# Behaviour against a fake library
# ---------------------------------------------------------------------------


class FakeLib:
    """Records calls; every attribute is a configurable callable."""

    def __init__(self, **fns):
        self.calls = []
        self.__dict__.update(fns)

    def __getattr__(self, name):  # only reached for undefined attributes
        raise AttributeError(name)


@pytest.fixture
def fake(monkeypatch):
    def install(**fns):
        fl = FakeLib(**fns)
        monkeypatch.setattr(cie, "lib", fl)
        return fl

    return install


def test_verify_returns_count_when_equal_to_sign_count(fake):
    fake(cie_verify=lambda *a: 3, cie_get_sign_count=lambda: 3)
    assert cie.verify("f.pdf") == 3


def test_verify_zero_signatures(fake):
    fake(cie_verify=lambda *a: 0, cie_get_sign_count=lambda: 0)
    assert cie.verify("f.pdf") == 0


@pytest.mark.parametrize(
    "rv",
    [
        0x84000002,  # CIE_SIGN_ERROR_FILE_NOT_FOUND
        0x84000005,  # CIE_SIGN_ERROR_INVALID_FILE
        2**64 - 1,  # negative status cast to a 64-bit CK_RV
        2**32 - 7,  # negative status cast to a 32-bit CK_RV
        5,  # small, but different from cie_get_sign_count()
    ],
)
def test_verify_error_when_different_from_sign_count(fake, rv):
    fake(cie_verify=lambda *a: rv, cie_get_sign_count=lambda: 0)
    with pytest.raises(PKCS11Error) as exc:
        cie.verify("f.pdf")
    assert exc.value.rv == rv


def test_verify_passes_proxy_arguments(fake):
    seen = []

    def verify(*a):
        seen.append(a)
        return 0

    fake(cie_verify=verify, cie_get_sign_count=lambda: 0)
    cie.verify("f.pdf", "proxy", 8080, "u:p")
    assert seen == [(b"f.pdf", b"proxy", 8080, b"u:p")]
    seen.clear()
    cie.verify("f.pdf")
    assert seen == [(b"f.pdf", None, 0, None)]


def test_get_sign_count_error(fake):
    fake(cie_get_sign_count=lambda: 0x84000001)
    with pytest.raises(PKCS11Error):
        cie.get_sign_count()
    fake(cie_get_sign_count=lambda: 2)
    assert cie.get_sign_count() == 2


def _dgs_fake(fake, rv, kind=0, sw=0, mrz=b"MRZ", photo=b"PNG"):
    state = {}

    def read(secret, mrz_buf, mrz_len, photo_buf, photo_len):
        state["secret"] = secret
        state["mrz_cap"] = mrz_len._obj.value
        state["photo_cap"] = photo_len._obj.value
        if rv == 0:
            ctypes.memmove(mrz_buf, mrz, len(mrz))
            mrz_len._obj.value = len(mrz)
            ctypes.memmove(photo_buf, photo, len(photo))
            photo_len._obj.value = len(photo)
        return rv

    def last_error(kind_ref, sw_ref):
        kind_ref._obj.value = kind
        sw_ref._obj.value = sw
        return 0

    fake(
        cie_read_dgs_can=read,
        cie_read_dgs=read,
        cie_last_error=last_error,
    )
    return state


def test_read_dgs_can_success(fake):
    state = _dgs_fake(fake, 0, mrz=b"P<ITA", photo=b"\x89PNG")
    assert cie.read_dgs_can("123456") == (b"P<ITA", b"\x89PNG")
    assert state["secret"] == b"123456"
    assert state["mrz_cap"] >= 4096
    assert state["photo_cap"] >= 524288


def test_read_dgs_pin_success(fake):
    state = _dgs_fake(fake, 0)
    assert cie.read_dgs("12345678") == (b"MRZ", b"PNG")
    assert state["secret"] == b"12345678"


def test_read_dgs_can_wrong_can(fake):
    _dgs_fake(fake, _ffi.CKR_PIN_INCORRECT, kind=_ffi.CIE_ERR_WRONG_CAN)
    with pytest.raises(cie.WrongCanError) as exc:
        cie.read_dgs_can("123456")
    assert isinstance(exc.value, PKCS11Error)
    assert exc.value.rv == _ffi.CKR_PIN_INCORRECT
    assert exc.value.kind == _ffi.CIE_ERR_WRONG_CAN


def test_read_dgs_can_extended_length_not_supported(fake):
    _dgs_fake(
        fake, _ffi.CKR_DEVICE_ERROR, kind=_ffi.CIE_ERR_INS_NOT_SUPPORTED, sw=0x6D00
    )
    with pytest.raises(cie.CieError) as exc:
        cie.read_dgs_can("123456")
    assert not isinstance(exc.value, cie.WrongCanError)
    assert exc.value.kind == _ffi.CIE_ERR_INS_NOT_SUPPORTED
    assert exc.value.sw == 0x6D00


def test_read_dgs_can_no_pace(fake):
    _dgs_fake(fake, _ffi.CKR_FUNCTION_NOT_SUPPORTED, kind=_ffi.CIE_ERR_UNSUPPORTED_CARD)
    with pytest.raises(cie.CieError) as exc:
        cie.read_dgs_can("123456")
    assert exc.value.kind == _ffi.CIE_ERR_UNSUPPORTED_CARD
    assert exc.value.rv == _ffi.CKR_FUNCTION_NOT_SUPPORTED


def test_read_dgs_can_arguments_bad(fake):
    _dgs_fake(fake, _ffi.CKR_ARGUMENTS_BAD)
    with pytest.raises(PKCS11Error) as exc:
        cie.read_dgs_can("12345")
    assert exc.value.rv == _ffi.CKR_ARGUMENTS_BAD
    assert not isinstance(exc.value, cie.CieError)


def test_wrong_can_kind_requires_pin_incorrect_rv(fake):
    # A stale WRONG_CAN kind must not relabel an unrelated failure.
    _dgs_fake(fake, _ffi.CKR_DEVICE_ERROR, kind=_ffi.CIE_ERR_WRONG_CAN)
    with pytest.raises(cie.CieError) as exc:
        cie.read_dgs_can("123456")
    assert not isinstance(exc.value, cie.WrongCanError)


def test_read_dgs_can_old_library_without_last_error(fake):
    def read(*a):
        return _ffi.CKR_PIN_INCORRECT

    fake(cie_read_dgs_can=read)
    with pytest.raises(PKCS11Error) as exc:
        cie.read_dgs_can("123456")
    assert exc.value.rv == _ffi.CKR_PIN_INCORRECT


def test_get_certificate_released_with_cie_free(fake):
    der = (ctypes.c_ubyte * 4)(1, 2, 3, 4)
    freed = []

    def get_cert(pan, out_ptr, out_len):
        ptr = ctypes.c_void_p(ctypes.addressof(der))
        ctypes.memmove(
            ctypes.addressof(out_ptr._obj), ctypes.byref(ptr), ctypes.sizeof(ptr)
        )
        out_len._obj.value = 4
        return 0

    fake(cie_get_certificate=get_cert, cie_free=lambda p: freed.append(p.value))
    assert cie.get_certificate("PAN") == b"\x01\x02\x03\x04"
    assert freed == [ctypes.addressof(der)]


def test_get_certificate_error_does_not_free(fake):
    freed = []
    fake(
        cie_get_certificate=lambda *a: _ffi.CKR_DEVICE_ERROR,
        cie_free=lambda p: freed.append(p),
    )
    with pytest.raises(PKCS11Error):
        cie.get_certificate("PAN")
    assert freed == []


def test_is_enabled_only_for_one(fake):
    fake(cie_is_enabled=lambda pan: 1)
    assert cie.is_enabled("PAN") is True
    fake(cie_is_enabled=lambda pan: 0)
    assert cie.is_enabled("PAN") is False


# ---------------------------------------------------------------------------
# Callbacks must never be NULL (the library calls them unconditionally)
# ---------------------------------------------------------------------------


def test_enable_passes_callable_callbacks_and_forwards_progress(fake):
    got = {}

    def enable(pan, pin, attempts, progress, completed):
        got["progress"] = progress
        got["completed"] = completed
        progress(42, b"halfway")
        completed(b"PAN", b"NAME", b"SER")
        attempts._obj.value = 3
        return 0

    fake(cie_enable=enable)
    events = []
    attempts = cie.enable(
        "PAN",
        "12345678",
        progress=lambda p, m: events.append(("progress", p, m)),
        completed=lambda *a: events.append(("completed", *a)),
    )
    assert attempts == 3
    assert got["progress"] is not None and got["completed"] is not None
    assert events == [("progress", 42, "halfway"), ("completed", "PAN", "NAME", "SER")]


def test_enable_without_callbacks_still_passes_non_null(fake):
    def enable(pan, pin, attempts, progress, completed):
        assert progress is not None and completed is not None
        progress(1, None)
        completed(None, None, None)
        return 0

    fake(cie_enable=enable)
    cie.enable("PAN", "12345678")


def test_wrong_pin_exposes_attempts(fake):
    def change(cur, new, attempts, progress):
        assert progress is not None
        attempts._obj.value = 2
        return _ffi.CKR_PIN_INCORRECT

    fake(cie_change_pin=change)
    with pytest.raises(PKCS11Error) as exc:
        cie.change_pin("00000000", "11111111")
    assert exc.value.rv == _ffi.CKR_PIN_INCORRECT
    assert exc.value.attempts == 2


def test_callback_exception_is_deferred_and_raised(fake):
    def unblock(puk, new, attempts, progress):
        progress(10, b"x")
        return 0

    fake(cie_unblock_pin=unblock)

    def boom(p, m):
        raise RuntimeError("boom")

    with pytest.raises(RuntimeError, match="boom"):
        cie.unblock_pin("1", "2", progress=boom)


def test_sign_and_timestamp_pass_non_null_callbacks(fake):
    seen = {}

    def sign(*a):
        seen["sign"] = (a[-2], a[-1], a[9], a[10])
        a[-1](0)
        return 0

    def ts(*a):
        seen["ts"] = a[-1]
        return 0

    fake(cie_sign=sign, cie_timestamp=ts)
    results = []
    cie.sign(
        "in.pdf",
        "PDF",
        "12345678",
        "PAN",
        0,
        0.1,
        0.1,
        0.4,
        0.1,
        None,
        "out.pdf",
        completed=results.append,
    )
    cie.timestamp("in.pdf", "https://tsa.example", out_token_path="o.tst")
    assert seen["sign"][0] is not None and seen["sign"][1] is not None
    assert seen["sign"][2] is None and seen["sign"][3] == 0
    assert seen["ts"] is not None
    assert results == [0]
