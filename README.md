# opencie-pkcs11-py

Python bindings for [libopencie-pkcs11](https://github.com/M0Rf30/opencie-pkcs11), providing a PKCS#11 interface and CIE-specific extensions for Italian Electronic Identity Cards.

## Installation

```bash
pip install opencie-pkcs11
```

### Build Requirements

- **libopencie-pkcs11** must be installed on your system
  - **libopencie-pkcs11 >= 1.3.0** is required (`cie.read_dgs_can()`,
    `cie_free`-based certificate release, CAN error kind, and the
    `cie.verify()` return-code contract). Older builds still import, but
    the new calls raise `AttributeError`.
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

cie.sign(in_file, "PDF", pin, pan, 0, 0.1, 0.1, 0.4, 0.1, image_data, out_file)
print(f"Document signed: {out_file}")

# Number of signatures found (0 if none). Raises PKCS11Error on failure.
sig_count = cie.verify(out_file)
print(f"Found {sig_count} signature(s)")

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

### CIE: Reading the MRZ and Photo (ICAO 9303)

```python
from opencie_pkcs11 import cie
from opencie_pkcs11.cie import WrongCanError
from opencie_pkcs11.pkcs11 import PKCS11Error

try:
    mrz, photo_png = cie.read_dgs_can("123456")  # 6-digit CAN printed on the card
except WrongCanError:
    raise SystemExit("Wrong CAN - do not retry with the same value")
except PKCS11Error as exc:
    # Readers without extended-length APDUs (e.g. ACS ACR122U) cannot run PACE:
    # CKR_DEVICE_ERROR + CIE_ERR_INS_NOT_SUPPORTED. Fall back to the PIN.
    if getattr(exc, "kind", None) == cie.CIE_ERR_INS_NOT_SUPPORTED:
        mrz, photo_png = cie.read_dgs("12345678")
    else:
        raise
```

`read_dgs_can` returns `CKR_PIN_INCORRECT` + `CIE_ERR_WRONG_CAN` (raised as
`WrongCanError`) for a wrong CAN, `CKR_FUNCTION_NOT_SUPPORTED` +
`CIE_ERR_UNSUPPORTED_CARD` when the chip has no supported PACE, and
`CKR_ARGUMENTS_BAD` for a CAN that is not exactly 6 digits. Failures that the
library classifies are raised as `CieError` (a `PKCS11Error` carrying `kind`
and `sw`).

## Notes

- **Callbacks**: libopencie-pkcs11 calls its progress/completion callbacks
  unconditionally and they must never be `NULL`; the bindings always pass
  native stubs. Pass `progress=callable(percentage, message)` (and
  `completed=` for `enable`/`sign`) to receive notifications. Exceptions raised
  by your callbacks are re-raised once the native call returns.
- **Verification**: `cie.verify()` returns the number of signatures found. A
  result different from `cie.get_sign_count()` is an error and raises
  `PKCS11Error` (`CIE_SIGN_ERROR_*`, 0x84000000 and up).
- **PIN attempts**: PIN-related failures expose the remaining attempts as
  `PKCS11Error.attempts`.
- **Library selection**: set `OPENCIE_PKCS11_LIB` to the absolute path of a
  specific `libopencie-pkcs11` build to bypass the dynamic linker search.
- **Thread Safety**: The underlying C library uses locking internally, but callers should still avoid concurrent calls against the same session or card from multiple threads without external synchronization.
- **Memory Management**: The bindings own all C memory allocated on your behalf (e.g. `cie_get_certificate`'s output buffer, released with `cie_free`) and free it before returning. Do not hold onto raw `ctypes` pointers from these calls.
- **Windows structs**: PKCS#11 structures are declared with 1-byte packing on Windows, matching `cryptoki.h`.

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