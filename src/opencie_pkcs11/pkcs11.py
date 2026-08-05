# SPDX-License-Identifier: MPL-2.0

"""Pythonic wrappers around the PKCS#11 C_* functions of libopencie-pkcs11."""

from __future__ import annotations

from ctypes import Array, cast, pointer
from dataclasses import dataclass

from opencie_pkcs11._ffi import (
    CK_ATTRIBUTE,
    CK_BYTE,
    CK_C_INITIALIZE_ARGS,
    CK_FALSE,
    CK_INFO,
    CK_MECHANISM,
    CK_OBJECT_HANDLE,
    CK_SESSION_INFO,
    CK_SLOT_INFO,
    CK_TOKEN_INFO,
    CK_TRUE,
    CK_ULONG,
    CK_UNAVAILABLE_INFORMATION,
    CK_UTF8CHAR,
    CK_VOID_PTR,
    CKA_CLASS,  # noqa: F401
    CKA_ID,  # noqa: F401
    CKA_LABEL,  # noqa: F401
    CKA_VALUE,  # noqa: F401
    CKF_OS_LOCKING_OK,
    CKF_RW_SESSION,  # noqa: F401
    CKF_SERIAL_SESSION,  # noqa: F401
    CKM_RSA_PKCS,  # noqa: F401
    CKM_SHA1_RSA_PKCS,  # noqa: F401
    CKM_SHA256,  # noqa: F401
    CKM_SHA256_RSA_PKCS,  # noqa: F401
    CKM_SHA384,  # noqa: F401
    CKM_SHA384_RSA_PKCS,  # noqa: F401
    CKM_SHA512,  # noqa: F401
    CKM_SHA512_RSA_PKCS,  # noqa: F401
    CKM_SHA_1,  # noqa: F401
    CKR_OK,
    CKU_CONTEXT_SPECIFIC,  # noqa: F401
    CKU_SO,  # noqa: F401
    CKU_USER,  # noqa: F401
    lib,
)

# Not part of the shared FFI contract: only needed to tolerate a benign
# GetAttributeValue result (unknown/sensitive attribute).
CKR_ATTRIBUTE_TYPE_INVALID = 0x00000012


class PKCS11Error(Exception):
    """Raised when a C_* call returns a CK_RV other than CKR_OK."""

    def __init__(self, rv: int) -> None:
        self.rv = rv
        super().__init__(f"CKR 0x{rv:08X}")


def _check_rv(rv: int) -> None:
    if rv != CKR_OK:
        raise PKCS11Error(rv)


def _pad_str(buf) -> str:
    """Decode a fixed-size CK_UTF8CHAR/char array, stripping space/NUL padding."""
    return bytes(buf).rstrip(b"\x00 ").decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Dataclasses mirroring the Go binding's Info/SlotInfo/TokenInfo/SessionInfo
# ---------------------------------------------------------------------------


@dataclass
class Info:
    cryptoki_version: tuple[int, int]
    manufacturer_id: str
    flags: int
    library_description: str
    library_version: tuple[int, int]


@dataclass
class SlotInfo:
    slot_description: str
    manufacturer_id: str
    flags: int
    hardware_version: tuple[int, int]
    firmware_version: tuple[int, int]


@dataclass
class TokenInfo:
    label: str
    manufacturer_id: str
    model: str
    serial_number: str
    flags: int
    max_session_count: int
    session_count: int
    max_rw_session_count: int
    rw_session_count: int
    max_pin_len: int
    min_pin_len: int
    total_public_memory: int
    free_public_memory: int
    total_private_memory: int
    free_private_memory: int
    hardware_version: tuple[int, int]
    firmware_version: tuple[int, int]
    utc_time: str


@dataclass
class SessionInfo:
    slot_id: int
    state: int
    flags: int
    device_error: int


# ---------------------------------------------------------------------------
# Buffer helpers
# ---------------------------------------------------------------------------


def _byte_buf(data: bytes) -> Array[CK_BYTE]:
    return (CK_BYTE * len(data)).from_buffer_copy(data)


def _make_mechanism(mech_type: int, param: bytes | None) -> CK_MECHANISM:
    """Build a CK_MECHANISM; keeps the parameter buffer alive on the struct."""
    mech = CK_MECHANISM(mechanism=mech_type)
    if param:
        buf = _byte_buf(param)
        mech.pParameter = cast(buf, CK_VOID_PTR)
        mech.ulParameterLen = len(param)
        mech._param_buf = buf  # keep alive for the lifetime of mech
    return mech


def _make_attrs(template: list[tuple[int, bytes | None]]) -> Array[CK_ATTRIBUTE]:
    """Build a CK_ATTRIBUTE array; keeps value buffers alive on the array."""
    attrs = (CK_ATTRIBUTE * len(template))()
    bufs = []
    for i, (attr_type, value) in enumerate(template):
        attrs[i].type = attr_type
        if value:
            buf = _byte_buf(value)
            attrs[i].pValue = cast(buf, CK_VOID_PTR)
            attrs[i].ulValueLen = len(value)
            bufs.append(buf)
    attrs._bufs = bufs  # keep alive for the lifetime of attrs
    return attrs


# ---------------------------------------------------------------------------
# General-purpose functions
# ---------------------------------------------------------------------------


def initialize() -> None:
    args = CK_C_INITIALIZE_ARGS(flags=CKF_OS_LOCKING_OK)
    _check_rv(lib.C_Initialize(cast(pointer(args), CK_VOID_PTR)))


def finalize() -> None:
    _check_rv(lib.C_Finalize(None))


def get_info() -> Info:
    info = CK_INFO()
    _check_rv(lib.C_GetInfo(info))
    return Info(
        cryptoki_version=(info.cryptokiVersion.major, info.cryptokiVersion.minor),
        manufacturer_id=_pad_str(info.manufacturerID),
        flags=info.flags,
        library_description=_pad_str(info.libraryDescription),
        library_version=(info.libraryVersion.major, info.libraryVersion.minor),
    )


def get_slot_list(token_present: bool) -> list[int]:
    present = CK_TRUE if token_present else CK_FALSE
    count = CK_ULONG(0)
    _check_rv(lib.C_GetSlotList(present, None, count))
    if count.value == 0:
        return []
    slots = (CK_ULONG * count.value)()
    _check_rv(lib.C_GetSlotList(present, slots, count))
    return list(slots[: count.value])


def get_slot_info(slot_id: int) -> SlotInfo:
    info = CK_SLOT_INFO()
    _check_rv(lib.C_GetSlotInfo(slot_id, info))
    return SlotInfo(
        slot_description=_pad_str(info.slotDescription),
        manufacturer_id=_pad_str(info.manufacturerID),
        flags=info.flags,
        hardware_version=(info.hardwareVersion.major, info.hardwareVersion.minor),
        firmware_version=(info.firmwareVersion.major, info.firmwareVersion.minor),
    )


def get_token_info(slot_id: int) -> TokenInfo:
    info = CK_TOKEN_INFO()
    _check_rv(lib.C_GetTokenInfo(slot_id, info))
    return TokenInfo(
        label=_pad_str(info.label),
        manufacturer_id=_pad_str(info.manufacturerID),
        model=_pad_str(info.model),
        serial_number=_pad_str(info.serialNumber),
        flags=info.flags,
        max_session_count=info.ulMaxSessionCount,
        session_count=info.ulSessionCount,
        max_rw_session_count=info.ulMaxRwSessionCount,
        rw_session_count=info.ulRwSessionCount,
        max_pin_len=info.ulMaxPinLen,
        min_pin_len=info.ulMinPinLen,
        total_public_memory=info.ulTotalPublicMemory,
        free_public_memory=info.ulFreePublicMemory,
        total_private_memory=info.ulTotalPrivateMemory,
        free_private_memory=info.ulFreePrivateMemory,
        hardware_version=(info.hardwareVersion.major, info.hardwareVersion.minor),
        firmware_version=(info.firmwareVersion.major, info.firmwareVersion.minor),
        utc_time=_pad_str(info.utcTime),
    )


def open_session(slot_id: int, flags: int) -> int:
    session = CK_ULONG(0)
    _check_rv(lib.C_OpenSession(slot_id, flags, None, None, session))
    return session.value


def close_session(session: int) -> None:
    _check_rv(lib.C_CloseSession(session))


def close_all_sessions(slot_id: int) -> None:
    _check_rv(lib.C_CloseAllSessions(slot_id))


def get_session_info(session: int) -> SessionInfo:
    info = CK_SESSION_INFO()
    _check_rv(lib.C_GetSessionInfo(session, info))
    return SessionInfo(
        slot_id=info.slotID,
        state=info.state,
        flags=info.flags,
        device_error=info.ulDeviceError,
    )


def login(session: int, user_type: int, pin: str) -> None:
    pin_bytes = pin.encode("utf-8")
    buf = (
        (CK_UTF8CHAR * len(pin_bytes)).from_buffer_copy(pin_bytes)
        if pin_bytes
        else None
    )
    _check_rv(lib.C_Login(session, user_type, buf, len(pin_bytes)))


def logout(session: int) -> None:
    _check_rv(lib.C_Logout(session))


# ---------------------------------------------------------------------------
# Object management
# ---------------------------------------------------------------------------


def find_objects_init(session: int, template: list[tuple[int, bytes | None]]) -> None:
    attrs = _make_attrs(template) if template else None
    _check_rv(lib.C_FindObjectsInit(session, attrs, len(template)))


def find_objects(session: int, max_count: int) -> list[int]:
    objects = (CK_OBJECT_HANDLE * max_count)()
    count = CK_ULONG(0)
    _check_rv(lib.C_FindObjects(session, objects, max_count, count))
    return list(objects[: count.value])


def find_objects_final(session: int) -> None:
    _check_rv(lib.C_FindObjectsFinal(session))


def get_attribute_value(
    session: int, obj: int, attrs: list[int]
) -> list[tuple[int, bytes | None]]:
    template = (CK_ATTRIBUTE * len(attrs))()
    for i, attr_type in enumerate(attrs):
        template[i].type = attr_type

    # First call: sizes only.
    rv = lib.C_GetAttributeValue(session, obj, template, len(attrs))
    if rv != CKR_OK and rv != CKR_ATTRIBUTE_TYPE_INVALID:
        _check_rv(rv)

    bufs: list[Array[CK_BYTE] | None] = [None] * len(attrs)
    for i in range(len(attrs)):
        length = template[i].ulValueLen
        if length and length != CK_UNAVAILABLE_INFORMATION:
            bufs[i] = (CK_BYTE * length)()
            template[i].pValue = cast(bufs[i], CK_VOID_PTR)
        else:
            template[i].pValue = None

    rv = lib.C_GetAttributeValue(session, obj, template, len(attrs))
    if rv != CKR_OK and rv != CKR_ATTRIBUTE_TYPE_INVALID:
        _check_rv(rv)

    result: list[tuple[int, bytes | None]] = []
    for i in range(len(attrs)):
        value = bytes(bufs[i]) if bufs[i] is not None else None
        result.append((template[i].type, value))
    return result


def set_attribute_value(
    session: int, obj: int, template: list[tuple[int, bytes]]
) -> None:
    attrs = _make_attrs(template)
    _check_rv(lib.C_SetAttributeValue(session, obj, attrs, len(template)))


def create_object(session: int, template: list[tuple[int, bytes]]) -> int:
    attrs = _make_attrs(template)
    obj = CK_OBJECT_HANDLE(0)
    _check_rv(lib.C_CreateObject(session, attrs, len(template), obj))
    return obj.value


def destroy_object(session: int, obj: int) -> None:
    _check_rv(lib.C_DestroyObject(session, obj))


# ---------------------------------------------------------------------------
# Encrypt / Decrypt
# ---------------------------------------------------------------------------


def encrypt_init(
    session: int, mechanism: int, key: int, param: bytes | None = None
) -> None:
    mech = _make_mechanism(mechanism, param)
    _check_rv(lib.C_EncryptInit(session, mech, key))


def encrypt(session: int, plaintext: bytes) -> bytes:
    src = _byte_buf(plaintext)
    out_len = CK_ULONG(0)
    _check_rv(lib.C_Encrypt(session, src, len(plaintext), None, out_len))
    out = (CK_BYTE * out_len.value)()
    _check_rv(lib.C_Encrypt(session, src, len(plaintext), out, out_len))
    return bytes(out[: out_len.value])


def decrypt_init(
    session: int, mechanism: int, key: int, param: bytes | None = None
) -> None:
    mech = _make_mechanism(mechanism, param)
    _check_rv(lib.C_DecryptInit(session, mech, key))


def decrypt(session: int, ciphertext: bytes) -> bytes:
    src = _byte_buf(ciphertext)
    out_len = CK_ULONG(0)
    _check_rv(lib.C_Decrypt(session, src, len(ciphertext), None, out_len))
    out = (CK_BYTE * out_len.value)()
    _check_rv(lib.C_Decrypt(session, src, len(ciphertext), out, out_len))
    return bytes(out[: out_len.value])


# ---------------------------------------------------------------------------
# Sign / Verify
# ---------------------------------------------------------------------------


def sign_init(
    session: int, mechanism: int, key: int, param: bytes | None = None
) -> None:
    mech = _make_mechanism(mechanism, param)
    _check_rv(lib.C_SignInit(session, mech, key))


def sign(session: int, data: bytes) -> bytes:
    src = _byte_buf(data)
    sig_len = CK_ULONG(0)
    _check_rv(lib.C_Sign(session, src, len(data), None, sig_len))
    sig = (CK_BYTE * sig_len.value)()
    _check_rv(lib.C_Sign(session, src, len(data), sig, sig_len))
    return bytes(sig[: sig_len.value])


def sign_update(session: int, data: bytes) -> None:
    src = _byte_buf(data)
    _check_rv(lib.C_SignUpdate(session, src, len(data)))


def sign_final(session: int) -> bytes:
    sig_len = CK_ULONG(0)
    _check_rv(lib.C_SignFinal(session, None, sig_len))
    sig = (CK_BYTE * sig_len.value)()
    _check_rv(lib.C_SignFinal(session, sig, sig_len))
    return bytes(sig[: sig_len.value])


def verify_init(
    session: int, mechanism: int, key: int, param: bytes | None = None
) -> None:
    mech = _make_mechanism(mechanism, param)
    _check_rv(lib.C_VerifyInit(session, mech, key))


def verify(session: int, data: bytes, signature: bytes) -> None:
    src = _byte_buf(data)
    sig = _byte_buf(signature)
    _check_rv(lib.C_Verify(session, src, len(data), sig, len(signature)))


# ---------------------------------------------------------------------------
# Digest
# ---------------------------------------------------------------------------


def digest_init(session: int, mechanism: int, param: bytes | None = None) -> None:
    mech = _make_mechanism(mechanism, param)
    _check_rv(lib.C_DigestInit(session, mech))


def digest(session: int, data: bytes) -> bytes:
    src = _byte_buf(data)
    out_len = CK_ULONG(0)
    _check_rv(lib.C_Digest(session, src, len(data), None, out_len))
    out = (CK_BYTE * out_len.value)()
    _check_rv(lib.C_Digest(session, src, len(data), out, out_len))
    return bytes(out[: out_len.value])


def digest_update(session: int, data: bytes) -> None:
    src = _byte_buf(data)
    _check_rv(lib.C_DigestUpdate(session, src, len(data)))


def digest_final(session: int) -> bytes:
    out_len = CK_ULONG(0)
    _check_rv(lib.C_DigestFinal(session, None, out_len))
    out = (CK_BYTE * out_len.value)()
    _check_rv(lib.C_DigestFinal(session, out, out_len))
    return bytes(out[: out_len.value])


# ---------------------------------------------------------------------------
# Key generation / randomness
# ---------------------------------------------------------------------------


def generate_key(
    session: int,
    mechanism: int,
    template: list[tuple[int, bytes]],
    param: bytes | None = None,
) -> int:
    mech = _make_mechanism(mechanism, param)
    attrs = _make_attrs(template)
    key = CK_OBJECT_HANDLE(0)
    _check_rv(lib.C_GenerateKey(session, mech, attrs, len(template), key))
    return key.value


def generate_key_pair(
    session: int,
    mechanism: int,
    pub_template: list[tuple[int, bytes]],
    priv_template: list[tuple[int, bytes]],
    param: bytes | None = None,
) -> tuple[int, int]:
    mech = _make_mechanism(mechanism, param)
    pub_attrs = _make_attrs(pub_template)
    priv_attrs = _make_attrs(priv_template)
    pub_key = CK_OBJECT_HANDLE(0)
    priv_key = CK_OBJECT_HANDLE(0)
    _check_rv(
        lib.C_GenerateKeyPair(
            session,
            mech,
            pub_attrs,
            len(pub_template),
            priv_attrs,
            len(priv_template),
            pub_key,
            priv_key,
        )
    )
    return pub_key.value, priv_key.value


def seed_random(session: int, seed: bytes) -> None:
    buf = _byte_buf(seed)
    _check_rv(lib.C_SeedRandom(session, buf, len(seed)))


def generate_random(session: int, length: int) -> bytes:
    buf = (CK_BYTE * length)()
    _check_rv(lib.C_GenerateRandom(session, buf, length))
    return bytes(buf)
