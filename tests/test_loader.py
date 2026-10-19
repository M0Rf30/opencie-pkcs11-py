# SPDX-License-Identifier: MPL-2.0

"""Loader error paths. Each case runs in a fresh interpreter because the
library is bound at import time."""

import ctypes
import ctypes.util
import subprocess
import sys

import pytest

from opencie_pkcs11 import _ffi

_RELEASES = "https://github.com/M0Rf30/opencie-pkcs11/releases"


def _import_with_lib(path: str) -> subprocess.CompletedProcess:
    import os

    env = {**os.environ, "OPENCIE_PKCS11_LIB": path}
    return subprocess.run(
        [sys.executable, "-c", "import opencie_pkcs11"],
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )


def test_missing_library_message():
    proc = _import_with_lib("/nonexistent/libopencie-pkcs11.so")
    assert proc.returncode != 0
    assert "LibraryLoadError" in proc.stderr
    assert "libopencie-pkcs11" in proc.stderr
    assert "OPENCIE_PKCS11_LIB" in proc.stderr
    assert _RELEASES in proc.stderr


def test_too_old_library_message():
    # libc exports none of the 1.3.0 symbols, so it stands in for an old build.
    libc = ctypes.util.find_library("c")
    if libc is None:
        pytest.skip("libc not locatable")
    proc = _import_with_lib(libc)
    assert proc.returncode != 0
    assert "cie_read_dgs_can" in proc.stderr
    assert ">= 1.3.0" in proc.stderr
    assert "OPENCIE_PKCS11_LIB" in proc.stderr
    assert _RELEASES in proc.stderr


def test_error_is_import_error():
    assert issubclass(_ffi.LibraryLoadError, ImportError)


def test_installed_library_passes_version_check():
    _ffi._check_version(_ffi.lib, "libopencie-pkcs11")
