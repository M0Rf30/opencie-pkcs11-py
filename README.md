# opencie-pkcs11-py

Python bindings for [libopencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11), providing a PKCS#11 interface and CIE-specific extensions for Italian Electronic Identity Cards.

## Installation

```bash
pip install opencie-pkcs11
```

### Build Requirements

- **libopencie-pkcs11** must be installed on your system
  - See [opencie-pkcs11 releases](https://github.com/M0Rf30/opencie-pkcs11/releases) for pre-built binaries
  - Or build from [source](https://github.com/M0Rf30/opencie-pkcs11)
- Python **>=3.10**

The bindings use [`ctypes`](https://docs.python.org/3/library/ctypes.html) — no compiled extension, no third-party dependencies. `libopencie-pkcs11` is located at import time via the standard dynamic linker search path (`LD_LIBRARY_PATH` on Linux, `DYLD_LIBRARY_PATH` on macOS, `PATH` on Windows).

## Modules

This package provides two modules:

### 1. `pkcs11` — Standard PKCS#11 Interface

Wraps the standard PKCS#11 cryptographic token interface. Provides access to:
- Session management
- Object handling (keys, certificates)
- Cryptographic operations (sign, verify, encrypt, decrypt, digest)
- Key generation
- Random number generation

### 2. `cie` — CIE-Specific Extensions

Wraps CIE card enrolment, PIN management, signing, and verification functions specific to Italian Electronic Identity Cards.

## Usage Examples

### PKCS#11: Basic Token Operations

```python
from opencie_pkcs11 import pkcs11

pkcs11.initialize()
try:
    info = pkcs11.get_info()
    print(f"Library: {info.library_description}")

    slots = pkcs11.get_slot_list(token_present=True)
    print(f"Found {len(slots)} slot(s) with tokens")
    if not slots:
        raise SystemExit

    session = pkcs11.open_session(slots[0], pkcs11.CKF_SERIAL_SESSION | pkcs11.CKF_RW_SESSION)
    try:
        pkcs11.login(session, pkcs11.CKU_USER, "12345678")
        try:
            print("Logged in successfully")
        finally:
            pkcs11.logout(session)
    finally:
        pkcs11.close_session(session)
finally:
    pkcs11.finalize()
```

### CIE: Enrolment and PIN Management

```python
from opencie_pkcs11 import cie
from opencie_pkcs11.pkcs11 import PKCS11Error

pan = "1234567890123456"
pin = "12345678"

if cie.is_enabled(pan):
    print("Card is already enrolled")
else:
    try:
        cie.enable(pan, pin)
        print("Card enrolled successfully")
    except PKCS11Error as exc:
        raise SystemExit(f"Enrolment failed: {exc}")

    new_pin = "87654321"
    attempts_left = cie.change_pin(pin, new_pin)
    print(f"PIN changed successfully ({attempts_left} attempts remaining)")
```

### CIE: PDF Signing and Verification

```python
from pathlib import Path

from opencie_pkcs11 import cie

pan = "1234567890123456"
pin = "12345678"
in_file = "document.pdf"
out_file = "document_signed.pdf"

image_data = Path("signature.png").read_bytes()

cie.sign(in_file, "PDF", pin, pan, 0, 100, 100, 200, 50, image_data, out_file)
print(f"Document signed: {out_file}")

sig_count = cie.verify(out_file)
print(f"Found {sig_count} valid signature(s)")

for i in range(sig_count):
    info = cie.get_verify_info(i)
    print(f"Signer #{i + 1}: {info.name} {info.surname} ({info.cn})")
    print(f"  Signed at: {info.signing_time}")
    print(f"  Valid: {info.is_sign_valid}")
```

### CIE: Reader Management

```python
from opencie_pkcs11 import cie

n = cie.reader_count()
print(f"Readers attached: {n}")

if n > 0:
    name = cie.reader_name()
    if name:
        print(f"First reader: {name}")

print("Waiting for reader change...")
n = cie.reader_watch(n)
print(f"Reader count is now: {n}")
```

## Limitations

- **Callbacks**: Progress and completion callbacks are not exposed. `NULL` is always passed to the underlying `PROGRESS_CALLBACK`/`COMPLETED_CALLBACK`/`SIGN_COMPLETED_CALLBACK` parameters; long-running calls (enrolment, signing, PIN operations) block until completion with no progress reporting.
- **Thread Safety**: The underlying C library uses locking internally, but callers should still avoid concurrent calls against the same session or card from multiple threads without external synchronization.
- **Memory Management**: The bindings own all C memory allocated on your behalf (e.g. `cie_get_certificate`'s output buffer) and free it before returning. Do not hold onto raw `ctypes` pointers from these calls.

## Platform Support

- **Linux** (x86_64, aarch64)
- **Windows** (x86_64)
- **macOS** (arm64)
- **Android** (arm64, experimental)

## License

This Python package (the bindings in this repository) is licensed under the
**Mozilla Public License 2.0** (MPL-2.0). See [`LICENSE`](LICENSE).

The underlying C library [`libopencie-pkcs11`](https://github.com/M0Rf30/opencie-pkcs11)
is distributed under the **GNU Lesser General Public License v3.0** (LGPL-3.0);
see its [`LICENSE.md`](https://github.com/M0Rf30/opencie-pkcs11/blob/main/LICENSE.md).
Any application that links these bindings against `libopencie-pkcs11` constitutes a
combined work and must additionally comply with the terms of LGPL-3.0.

## Links

- **Upstream C library**: [github.com/M0Rf30/opencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11)
- **This repository**: [github.com/M0Rf30/opencie-pkcs11-py](https://github.com/M0Rf30/opencie-pkcs11-py)
- **CIE Official Site**: [www.cartaidentita.interno.gov.it](https://www.cartaidentita.interno.gov.it/)

---

**Maintained by**: Gianluca Boiano ([@M0Rf30](https://github.com/M0Rf30))