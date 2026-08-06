# SPDX-License-Identifier: MPL-2.0

"""Tests for CIE error classification functions."""

import pytest

from opencie_pkcs11 import cie
from opencie_pkcs11._ffi import (
    CIE_ERR_CARD_COMMUNICATION,
    CIE_ERR_FILE_NOT_FOUND,
    CIE_ERR_INS_NOT_SUPPORTED,
    CIE_ERR_NONE,
    CIE_ERR_PIN_BLOCKED,
    CIE_ERR_PIN_NOT_SET,
    CIE_ERR_SECURITY_NOT_SATISFIED,
    CIE_ERR_UNKNOWN,
    CIE_ERR_WRONG_PARAMS,
    CIE_ERR_WRONG_PIN,
    lib,
)


def test_error_kind_constants():
    """Verify error kind constants match the contract."""
    assert CIE_ERR_NONE == 0
    assert CIE_ERR_WRONG_PIN == 1
    assert CIE_ERR_PIN_BLOCKED == 2
    assert CIE_ERR_PIN_NOT_SET == 3
    assert CIE_ERR_SECURITY_NOT_SATISFIED == 4
    assert CIE_ERR_FILE_NOT_FOUND == 5
    assert CIE_ERR_WRONG_PARAMS == 6
    assert CIE_ERR_INS_NOT_SUPPORTED == 7
    assert CIE_ERR_CARD_COMMUNICATION == 8
    assert CIE_ERR_UNKNOWN == 9


@pytest.mark.skipif(
    not hasattr(lib, "cie_classify_sw"),
    reason="libopencie-pkcs11 lacks cie_classify_sw (requires error classification support)",
)
def test_classify_sw_valid():
    """Test classify_sw with valid status words."""
    # 0x9000 is the success status word
    assert cie.classify_sw(0x9000) == CIE_ERR_NONE


@pytest.mark.skipif(
    not hasattr(lib, "cie_classify_sw"),
    reason="libopencie-pkcs11 lacks cie_classify_sw (requires error classification support)",
)
def test_classify_sw_out_of_range():
    """Test classify_sw maps unknown returns to CIE_ERR_UNKNOWN."""
    # A status word that classifies to UNKNOWN (native code returns 9 or unknown value)
    result = cie.classify_sw(0xFFFF)
    assert result in (CIE_ERR_UNKNOWN, 9)


def test_classify_sw_missing_symbol():
    """Test classify_sw raises AttributeError when symbol unavailable."""
    if hasattr(lib, "cie_classify_sw"):
        pytest.skip("cie_classify_sw is available, skipping missing symbol test")
    with pytest.raises(
        AttributeError,
        match="cie_classify_sw not available",
    ):
        cie.classify_sw(0x9000)


@pytest.mark.skipif(
    not hasattr(lib, "cie_last_error"),
    reason="libopencie-pkcs11 lacks cie_last_error (requires error classification support)",
)
def test_last_error_return_type():
    """Test last_error returns a tuple of two integers."""
    kind, sw = cie.last_error()
    assert isinstance(kind, int)
    assert isinstance(sw, int)
    # After a successful call, should be NONE/0
    assert kind == CIE_ERR_NONE or kind == 0


def test_last_error_missing_symbol():
    """Test last_error raises AttributeError when symbol unavailable."""
    if hasattr(lib, "cie_last_error"):
        pytest.skip("cie_last_error is available, skipping missing symbol test")
    with pytest.raises(
        AttributeError,
        match="cie_last_error not available",
    ):
        cie.last_error()


def test_cie_module_has_classify_sw():
    """Test that cie module exports classify_sw."""
    assert hasattr(cie, "classify_sw")
    assert callable(cie.classify_sw)


def test_cie_module_has_last_error():
    """Test that cie module exports last_error."""
    assert hasattr(cie, "last_error")
    assert callable(cie.last_error)
