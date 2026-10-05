# SPDX-License-Identifier: MPL-2.0

"""Low-level ctypes declarations for libopencie-pkcs11."""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from ctypes import (
    CFUNCTYPE,
    POINTER,
    Structure,
    c_char,
    c_char_p,
    c_float,
    c_int,
    c_size_t,
    c_ubyte,
    c_uint16,
    c_ulong,
)

# ---------------------------------------------------------------------------
# PKCS#11 type aliases
# ---------------------------------------------------------------------------

CK_RV = c_ulong
CK_SLOT_ID = c_ulong
CK_SESSION_HANDLE = c_ulong
CK_OBJECT_HANDLE = c_ulong
CK_FLAGS = c_ulong
CK_USER_TYPE = c_ulong
CK_BBOOL = c_ubyte
CK_BYTE = c_ubyte
CK_ULONG = c_ulong
CK_MECHANISM_TYPE = c_ulong
CK_ATTRIBUTE_TYPE = c_ulong
CK_VOID_PTR = ctypes.c_void_p
CK_STATE = c_ulong
CK_UTF8CHAR = c_ubyte

CK_TRUE: int = 1
CK_FALSE: int = 0

# Common return codes
CKR_OK = 0x00000000
CKR_HOST_MEMORY = 0x00000002
CKR_GENERAL_ERROR = 0x00000005
CKR_FUNCTION_FAILED = 0x00000006
CKR_ARGUMENTS_BAD = 0x00000007
CKR_DEVICE_ERROR = 0x00000030
CKR_FUNCTION_NOT_SUPPORTED = 0x00000054
CKR_PIN_INCORRECT = 0x000000A0
CKR_PIN_LOCKED = 0x000000A4
CKR_BUFFER_TOO_SMALL = 0x00000150
CKR_TOKEN_NOT_PRESENT = 0x000000E0
CKR_TOKEN_NOT_RECOGNIZED = 0x000000E1

# Session flags
CKF_SERIAL_SESSION = 0x00000004
CKF_RW_SESSION = 0x00000002
CKF_OS_LOCKING_OK = 0x00000002

# User types
CKU_SO = 0
CKU_USER = 1
CKU_CONTEXT_SPECIFIC = 2

# Object class
CKO_CERTIFICATE = 0x00000001
CKO_PUBLIC_KEY = 0x00000002
CKO_PRIVATE_KEY = 0x00000003

# Attribute types
CKA_CLASS = 0x00000000
CKA_TOKEN = 0x00000001
CKA_LABEL = 0x00000003
CKA_VALUE = 0x00000011
CKA_CERTIFICATE_TYPE = 0x00000080
CKA_SUBJECT = 0x00000101
CKA_ID = 0x00000102
CKA_ISSUER = 0x00000081
CKA_SERIAL_NUMBER = 0x00000082
CKA_MODULUS = 0x00000120
CKA_PUBLIC_EXPONENT = 0x00000122
CKA_KEY_TYPE = 0x00000100

# Mechanism types
CKM_RSA_PKCS = 0x00000001
CKM_RSA_X_509 = 0x00000003
CKM_SHA_1 = 0x00000220
CKM_SHA256 = 0x00000250
CKM_SHA384 = 0x00000260
CKM_SHA512 = 0x00000270
CKM_SHA1_RSA_PKCS = 0x00000006
CKM_SHA256_RSA_PKCS = 0x00000040
CKM_SHA384_RSA_PKCS = 0x00000041
CKM_SHA512_RSA_PKCS = 0x00000042

# Unavailable information sentinel
CK_UNAVAILABLE_INFORMATION = c_ulong(-1).value


# ---------------------------------------------------------------------------
# PKCS#11 structures
# ---------------------------------------------------------------------------

# cryptoki.h wraps every PKCS#11 struct in `#pragma pack(push, cryptoki, 1)`
# on Windows only; elsewhere the natural alignment applies.


class _CkStruct(Structure):
    """Base of every PKCS#11 struct (packed on Windows, native layout elsewhere)."""

    if sys.platform == "win32":
        _pack_ = 1


class CK_VERSION(_CkStruct):
    _fields_ = [("major", CK_BYTE), ("minor", CK_BYTE)]


class CK_INFO(_CkStruct):
    _fields_ = [
        ("cryptokiVersion", CK_VERSION),
        ("manufacturerID", CK_UTF8CHAR * 32),
        ("flags", CK_FLAGS),
        ("libraryDescription", CK_UTF8CHAR * 32),
        ("libraryVersion", CK_VERSION),
    ]


class CK_SLOT_INFO(_CkStruct):
    _fields_ = [
        ("slotDescription", CK_UTF8CHAR * 64),
        ("manufacturerID", CK_UTF8CHAR * 32),
        ("flags", CK_FLAGS),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
    ]


class CK_TOKEN_INFO(_CkStruct):
    _fields_ = [
        ("label", CK_UTF8CHAR * 32),
        ("manufacturerID", CK_UTF8CHAR * 32),
        ("model", CK_UTF8CHAR * 16),
        ("serialNumber", c_char * 16),
        ("flags", CK_FLAGS),
        ("ulMaxSessionCount", CK_ULONG),
        ("ulSessionCount", CK_ULONG),
        ("ulMaxRwSessionCount", CK_ULONG),
        ("ulRwSessionCount", CK_ULONG),
        ("ulMaxPinLen", CK_ULONG),
        ("ulMinPinLen", CK_ULONG),
        ("ulTotalPublicMemory", CK_ULONG),
        ("ulFreePublicMemory", CK_ULONG),
        ("ulTotalPrivateMemory", CK_ULONG),
        ("ulFreePrivateMemory", CK_ULONG),
        ("hardwareVersion", CK_VERSION),
        ("firmwareVersion", CK_VERSION),
        ("utcTime", c_char * 16),
    ]


class CK_SESSION_INFO(_CkStruct):
    _fields_ = [
        ("slotID", CK_SLOT_ID),
        ("state", CK_STATE),
        ("flags", CK_FLAGS),
        ("ulDeviceError", CK_ULONG),
    ]


class CK_MECHANISM(_CkStruct):
    _fields_ = [
        ("mechanism", CK_MECHANISM_TYPE),
        ("pParameter", CK_VOID_PTR),
        ("ulParameterLen", CK_ULONG),
    ]


class CK_ATTRIBUTE(_CkStruct):
    _fields_ = [
        ("type", CK_ATTRIBUTE_TYPE),
        ("pValue", CK_VOID_PTR),
        ("ulValueLen", CK_ULONG),
    ]


class CK_C_INITIALIZE_ARGS(_CkStruct):
    _fields_ = [
        ("CreateMutex", CK_VOID_PTR),
        ("DestroyMutex", CK_VOID_PTR),
        ("LockMutex", CK_VOID_PTR),
        ("UnlockMutex", CK_VOID_PTR),
        ("flags", CK_FLAGS),
        ("pReserved", CK_VOID_PTR),
    ]


# ---------------------------------------------------------------------------
# CIE structures
# ---------------------------------------------------------------------------

# CIE error kinds
CIE_ERR_NONE = 0
CIE_ERR_WRONG_PIN = 1
CIE_ERR_PIN_BLOCKED = 2
CIE_ERR_PIN_NOT_SET = 3
CIE_ERR_SECURITY_NOT_SATISFIED = 4
CIE_ERR_FILE_NOT_FOUND = 5
CIE_ERR_WRONG_PARAMS = 6
CIE_ERR_INS_NOT_SUPPORTED = 7
CIE_ERR_CARD_COMMUNICATION = 8
CIE_ERR_UNKNOWN = 9
CIE_ERR_UNSUPPORTED_CARD = 10
CIE_ERR_WRONG_CAN = 11

# Base of the CIE_SIGN_ERROR_* codes that cie_verify() may return as CK_RV.
CIE_SIGN_ERROR_BASE = 0x84000000

OPENCIE_MAX_LEN = 512


class VerifyInfoC(Structure):
    """Mirrors verifyInfo_t from cie_ext.h."""

    _fields_ = [
        ("name", c_char * (OPENCIE_MAX_LEN * 2)),
        ("surname", c_char * (OPENCIE_MAX_LEN * 2)),
        ("cn", c_char * (OPENCIE_MAX_LEN * 2)),
        ("signingTime", c_char * (OPENCIE_MAX_LEN * 2)),
        ("cadn", c_char * (OPENCIE_MAX_LEN * 2)),
        ("CertRevocStatus", c_int),
        ("isSignValid", c_int),
        ("isCertValid", c_int),
    ]


# ---------------------------------------------------------------------------
# Callback types
# ---------------------------------------------------------------------------

PROGRESS_CALLBACK = CFUNCTYPE(CK_RV, c_int, c_char_p)
COMPLETED_CALLBACK = CFUNCTYPE(CK_RV, c_char_p, c_char_p, c_char_p)
SIGN_COMPLETED_CALLBACK = CFUNCTYPE(CK_RV, c_int)

# ---------------------------------------------------------------------------
# Library loading
# ---------------------------------------------------------------------------

_LIB_NAMES = {
    "linux": "libopencie-pkcs11.so",
    "darwin": "libopencie-pkcs11.dylib",
    "win32": "opencie-pkcs11.dll",
}


def _load_library() -> ctypes.CDLL:
    # Explicit override (absolute path to the shared library), e.g. to pick a
    # specific release when several are installed.
    override = os.environ.get("OPENCIE_PKCS11_LIB")
    if override:
        return ctypes.CDLL(override)

    name = _LIB_NAMES.get(sys.platform)
    if name is None:
        name = "libopencie-pkcs11.so"

    # Try platform search first, then fall-back to the bare name.
    path = ctypes.util.find_library("opencie-pkcs11") or name
    return ctypes.CDLL(path)


lib = _load_library()

# ---------------------------------------------------------------------------
# PKCS#11 function prototypes
# ---------------------------------------------------------------------------

# C_Initialize
lib.C_Initialize.argtypes = [CK_VOID_PTR]
lib.C_Initialize.restype = CK_RV

# C_Finalize
lib.C_Finalize.argtypes = [CK_VOID_PTR]
lib.C_Finalize.restype = CK_RV

# C_GetInfo
lib.C_GetInfo.argtypes = [POINTER(CK_INFO)]
lib.C_GetInfo.restype = CK_RV

# C_GetSlotList
lib.C_GetSlotList.argtypes = [
    CK_BBOOL,
    POINTER(CK_SLOT_ID),
    POINTER(CK_ULONG),
]
lib.C_GetSlotList.restype = CK_RV

# C_GetSlotInfo
lib.C_GetSlotInfo.argtypes = [CK_SLOT_ID, POINTER(CK_SLOT_INFO)]
lib.C_GetSlotInfo.restype = CK_RV

# C_GetTokenInfo
lib.C_GetTokenInfo.argtypes = [CK_SLOT_ID, POINTER(CK_TOKEN_INFO)]
lib.C_GetTokenInfo.restype = CK_RV

# C_OpenSession
lib.C_OpenSession.argtypes = [
    CK_SLOT_ID,
    CK_FLAGS,
    CK_VOID_PTR,
    CK_VOID_PTR,
    POINTER(CK_SESSION_HANDLE),
]
lib.C_OpenSession.restype = CK_RV

# C_CloseSession
lib.C_CloseSession.argtypes = [CK_SESSION_HANDLE]
lib.C_CloseSession.restype = CK_RV

# C_CloseAllSessions
lib.C_CloseAllSessions.argtypes = [CK_SLOT_ID]
lib.C_CloseAllSessions.restype = CK_RV

# C_GetSessionInfo
lib.C_GetSessionInfo.argtypes = [CK_SESSION_HANDLE, POINTER(CK_SESSION_INFO)]
lib.C_GetSessionInfo.restype = CK_RV

# C_Login
lib.C_Login.argtypes = [
    CK_SESSION_HANDLE,
    CK_USER_TYPE,
    POINTER(CK_UTF8CHAR),
    CK_ULONG,
]
lib.C_Login.restype = CK_RV

# C_Logout
lib.C_Logout.argtypes = [CK_SESSION_HANDLE]
lib.C_Logout.restype = CK_RV

# C_FindObjectsInit
lib.C_FindObjectsInit.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
]
lib.C_FindObjectsInit.restype = CK_RV

# C_FindObjects
lib.C_FindObjects.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_OBJECT_HANDLE),
    CK_ULONG,
    POINTER(CK_ULONG),
]
lib.C_FindObjects.restype = CK_RV

# C_FindObjectsFinal
lib.C_FindObjectsFinal.argtypes = [CK_SESSION_HANDLE]
lib.C_FindObjectsFinal.restype = CK_RV

# C_GetAttributeValue
lib.C_GetAttributeValue.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
]
lib.C_GetAttributeValue.restype = CK_RV

# C_SetAttributeValue
lib.C_SetAttributeValue.argtypes = [
    CK_SESSION_HANDLE,
    CK_OBJECT_HANDLE,
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
]
lib.C_SetAttributeValue.restype = CK_RV

# C_CreateObject
lib.C_CreateObject.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
    POINTER(CK_OBJECT_HANDLE),
]
lib.C_CreateObject.restype = CK_RV

# C_DestroyObject
lib.C_DestroyObject.argtypes = [CK_SESSION_HANDLE, CK_OBJECT_HANDLE]
lib.C_DestroyObject.restype = CK_RV

# C_EncryptInit
lib.C_EncryptInit.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_MECHANISM),
    CK_OBJECT_HANDLE,
]
lib.C_EncryptInit.restype = CK_RV

# C_Encrypt
lib.C_Encrypt.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
    POINTER(CK_BYTE),
    POINTER(CK_ULONG),
]
lib.C_Encrypt.restype = CK_RV

# C_DecryptInit
lib.C_DecryptInit.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_MECHANISM),
    CK_OBJECT_HANDLE,
]
lib.C_DecryptInit.restype = CK_RV

# C_Decrypt
lib.C_Decrypt.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
    POINTER(CK_BYTE),
    POINTER(CK_ULONG),
]
lib.C_Decrypt.restype = CK_RV

# C_SignInit
lib.C_SignInit.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_MECHANISM),
    CK_OBJECT_HANDLE,
]
lib.C_SignInit.restype = CK_RV

# C_Sign
lib.C_Sign.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
    POINTER(CK_BYTE),
    POINTER(CK_ULONG),
]
lib.C_Sign.restype = CK_RV

# C_SignUpdate
lib.C_SignUpdate.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
]
lib.C_SignUpdate.restype = CK_RV

# C_SignFinal
lib.C_SignFinal.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    POINTER(CK_ULONG),
]
lib.C_SignFinal.restype = CK_RV

# C_VerifyInit
lib.C_VerifyInit.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_MECHANISM),
    CK_OBJECT_HANDLE,
]
lib.C_VerifyInit.restype = CK_RV

# C_Verify
lib.C_Verify.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
    POINTER(CK_BYTE),
    CK_ULONG,
]
lib.C_Verify.restype = CK_RV

# C_DigestInit
lib.C_DigestInit.argtypes = [CK_SESSION_HANDLE, POINTER(CK_MECHANISM)]
lib.C_DigestInit.restype = CK_RV

# C_Digest
lib.C_Digest.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
    POINTER(CK_BYTE),
    POINTER(CK_ULONG),
]
lib.C_Digest.restype = CK_RV

# C_DigestUpdate
lib.C_DigestUpdate.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
]
lib.C_DigestUpdate.restype = CK_RV

# C_DigestFinal
lib.C_DigestFinal.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    POINTER(CK_ULONG),
]
lib.C_DigestFinal.restype = CK_RV

# C_GenerateKey
lib.C_GenerateKey.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_MECHANISM),
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
    POINTER(CK_OBJECT_HANDLE),
]
lib.C_GenerateKey.restype = CK_RV

# C_GenerateKeyPair
lib.C_GenerateKeyPair.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_MECHANISM),
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
    POINTER(CK_ATTRIBUTE),
    CK_ULONG,
    POINTER(CK_OBJECT_HANDLE),
    POINTER(CK_OBJECT_HANDLE),
]
lib.C_GenerateKeyPair.restype = CK_RV

# C_SeedRandom
lib.C_SeedRandom.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
]
lib.C_SeedRandom.restype = CK_RV

# C_GenerateRandom
lib.C_GenerateRandom.argtypes = [
    CK_SESSION_HANDLE,
    POINTER(CK_BYTE),
    CK_ULONG,
]
lib.C_GenerateRandom.restype = CK_RV

# ---------------------------------------------------------------------------
# CIE extension prototypes
# ---------------------------------------------------------------------------

# cie_enable
lib.cie_enable.argtypes = [
    c_char_p,
    c_char_p,
    POINTER(c_int),
    PROGRESS_CALLBACK,
    COMPLETED_CALLBACK,
]
lib.cie_enable.restype = CK_RV

# cie_is_enabled
lib.cie_is_enabled.argtypes = [c_char_p]
lib.cie_is_enabled.restype = CK_RV

# cie_disable
lib.cie_disable.argtypes = [c_char_p]
lib.cie_disable.restype = CK_RV

# cie_change_pin
lib.cie_change_pin.argtypes = [
    c_char_p,
    c_char_p,
    POINTER(c_int),
    PROGRESS_CALLBACK,
]
lib.cie_change_pin.restype = CK_RV

# cie_unblock_pin
lib.cie_unblock_pin.argtypes = [
    c_char_p,
    c_char_p,
    POINTER(c_int),
    PROGRESS_CALLBACK,
]
lib.cie_unblock_pin.restype = CK_RV

# cie_sign
lib.cie_sign.argtypes = [
    c_char_p,  # inFilePath
    c_char_p,  # type
    c_char_p,  # pin
    c_char_p,  # pan
    c_int,  # page
    c_float,  # x
    c_float,  # y
    c_float,  # w
    c_float,  # h
    POINTER(c_ubyte),  # imageData
    c_int,  # imageDataLen
    c_char_p,  # outFilePath
    PROGRESS_CALLBACK,
    SIGN_COMPLETED_CALLBACK,
]
lib.cie_sign.restype = CK_RV

# cie_verify (returns CK_RV: signature count, 0 if none, or an error code;
# a value different from cie_get_sign_count() is an error)
lib.cie_verify.argtypes = [c_char_p, c_char_p, c_int, c_char_p]
lib.cie_verify.restype = CK_RV

# cie_get_sign_count (returns CK_RV: signature count or an error code)
lib.cie_get_sign_count.argtypes = []
lib.cie_get_sign_count.restype = CK_RV

# cie_get_verify_info
lib.cie_get_verify_info.argtypes = [c_int, POINTER(VerifyInfoC)]
lib.cie_get_verify_info.restype = CK_RV

# cie_extract_p7m
lib.cie_extract_p7m.argtypes = [c_char_p, c_char_p]
lib.cie_extract_p7m.restype = CK_RV

# cie_reader_count
lib.cie_reader_count.argtypes = []
lib.cie_reader_count.restype = c_int

# cie_reader_watch
lib.cie_reader_watch.argtypes = [c_int]
lib.cie_reader_watch.restype = c_int

# cie_reader_name
lib.cie_reader_name.argtypes = [c_char_p, c_int]
lib.cie_reader_name.restype = c_int

# ---------------------------------------------------------------------------
# Optional symbols. cie_get_certificate/cie_timestamp/cie_read_dgs appeared in
# libopencie-pkcs11 >= 1.0.6, cie_classify_sw/cie_last_error in >= 1.0.12 and
# cie_read_dgs_can/cie_free are part of the 1.3.0 public API. Wrapped in
# try/except so the bindings remain importable against older library builds
# that lack these exports; the corresponding Python wrappers raise
# AttributeError at call time.
# ---------------------------------------------------------------------------

try:
    lib.cie_get_certificate.argtypes = [
        c_char_p,
        POINTER(POINTER(c_ubyte)),
        POINTER(c_ulong),
    ]
    lib.cie_get_certificate.restype = CK_RV
except AttributeError:
    pass

try:
    lib.cie_timestamp.argtypes = [
        c_char_p,  # inFilePath
        c_char_p,  # tsaUrl
        c_char_p,  # tsaUsername
        c_char_p,  # tsaPassword
        c_char_p,  # outTokenPath
        PROGRESS_CALLBACK,
    ]
    lib.cie_timestamp.restype = CK_RV
except AttributeError:
    pass

try:
    lib.cie_read_dgs.argtypes = [
        c_char_p,  # pin
        c_char_p,  # mrzOut
        POINTER(c_size_t),  # mrzLen
        POINTER(c_ubyte),  # photoOut
        POINTER(c_size_t),  # photoLen
    ]
    lib.cie_read_dgs.restype = CK_RV
except AttributeError:
    pass

try:
    lib.make_digest_info.argtypes = [
        c_int,
        POINTER(c_ubyte),
        c_size_t,
        POINTER(c_ubyte),
        POINTER(c_size_t),
    ]
    lib.make_digest_info.restype = c_int
except AttributeError:
    pass

try:
    lib.cie_read_dgs_can.argtypes = [
        c_char_p,  # can (exactly 6 ASCII digits)
        c_char_p,  # mrzOut
        POINTER(c_size_t),  # mrzLen
        POINTER(c_ubyte),  # photoOut
        POINTER(c_size_t),  # photoLen
    ]
    lib.cie_read_dgs_can.restype = CK_RV
except AttributeError:
    pass

try:
    lib.cie_free.argtypes = [ctypes.c_void_p]
    lib.cie_free.restype = None
except AttributeError:
    pass

try:
    lib.cie_classify_sw.argtypes = [c_uint16]
    lib.cie_classify_sw.restype = c_int
except AttributeError:
    pass

try:
    lib.cie_last_error.argtypes = [
        POINTER(c_int),  # outKind
        POINTER(c_uint16),  # outSw
    ]
    lib.cie_last_error.restype = CK_RV
except AttributeError:
    pass
