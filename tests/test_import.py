# SPDX-License-Identifier: MPL-2.0

"""Package structure smoke tests. No smart card hardware in CI, so these
only verify the module surface and error types, never actual C calls."""


def test_pkcs11_module_has_initialize():
    from opencie_pkcs11 import pkcs11

    assert hasattr(pkcs11, "initialize")


def test_cie_module_has_enable():
    from opencie_pkcs11 import cie

    assert hasattr(cie, "enable")


def test_pkcs11_error_type():
    from opencie_pkcs11.pkcs11 import PKCS11Error

    err = PKCS11Error(0x30)
    assert err.rv == 0x30
    assert "0x00000030" in str(err).lower() or "0x00000030" in str(err)
