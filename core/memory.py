"""
Secure Memory Management Module
Provides memory locking (preventing swap/paging to disk) and secure memory wiping
(zeroing out cryptographic keys and sensitive plaintext in RAM).
"""

import sys
import ctypes
import os

# Windows API definitions for VirtualLock / VirtualUnlock
IS_WINDOWS = sys.platform.startswith("win")
if IS_WINDOWS:
    try:
        kernel32 = ctypes.windll.kernel32
        _VirtualLock = kernel32.VirtualLock
        _VirtualLock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _VirtualLock.restype = ctypes.c_int

        _VirtualUnlock = kernel32.VirtualUnlock
        _VirtualUnlock.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _VirtualUnlock.restype = ctypes.c_int
    except Exception:
        _VirtualLock = None
        _VirtualUnlock = None
else:
    _VirtualLock = None
    _VirtualUnlock = None


def zero_memory(target) -> bool:
    """
    Overwrites the memory buffer with zeros.
    Supports bytearray, ctypes character arrays/buffers.
    """
    if target is None:
        return False

    try:
        if isinstance(target, bytearray):
            c_target = (ctypes.c_char * len(target)).from_buffer(target)
            ctypes.memset(ctypes.addressof(c_target), 0, len(target))
            return True
        elif hasattr(target, "_type_") or isinstance(target, ctypes.Array):
            ctypes.memset(ctypes.addressof(target), 0, ctypes.sizeof(target))
            return True
        elif isinstance(target, list):
            for i in range(len(target)):
                target[i] = 0
            return True
    except Exception:
        # Fallback manual iteration if bytearray
        if isinstance(target, bytearray):
            for i in range(len(target)):
                target[i] = 0
            return True
    return False


def lock_memory_region(address: int, size: int) -> bool:
    """
    Locks the specified memory region into physical RAM to prevent paging to swap/disk.
    """
    if IS_WINDOWS and _VirtualLock is not None:
        try:
            res = _VirtualLock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return res != 0
        except Exception:
            return False
    return False


def unlock_memory_region(address: int, size: int) -> bool:
    """
    Unlocks a previously locked memory region.
    """
    if IS_WINDOWS and _VirtualUnlock is not None:
        try:
            res = _VirtualUnlock(ctypes.c_void_p(address), ctypes.c_size_t(size))
            return res != 0
        except Exception:
            return False
    return False


class SecureBuffer:
    """
    A managed mutable memory buffer for sensitive data (keys, passwords, plaintexts)
    that is locked in physical RAM (where supported) and guaranteed to be zeroed
    upon release or context exit.
    """

    def __init__(self, size_or_data):
        if isinstance(size_or_data, int):
            self.size = size_or_data
            self._buffer = bytearray(self.size)
        elif isinstance(size_or_data, (bytes, bytearray)):
            self.size = len(size_or_data)
            self._buffer = bytearray(size_or_data)
        else:
            raise TypeError("Expected int size or bytes/bytearray data")

        self._c_arr = (ctypes.c_char * self.size).from_buffer(self._buffer)
        self._addr = ctypes.addressof(self._c_arr)
        self.locked = lock_memory_region(self._addr, self.size)
        self.wiped = False

    def get_bytes(self) -> bytes:
        """Returns bytes copy for APIs that require immutable bytes."""
        if self.wiped:
            raise ValueError("Buffer has already been wiped")
        return bytes(self._buffer)

    def get_bytearray(self) -> bytearray:
        """Returns underlying bytearray."""
        if self.wiped:
            raise ValueError("Buffer has already been wiped")
        return self._buffer

    def wipe(self):
        """Zeroes memory immediately and unlocks region."""
        if not self.wiped:
            zero_memory(self._buffer)
            if self.locked:
                unlock_memory_region(self._addr, self.size)
                self.locked = False
            self.wiped = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.wipe()

    def __del__(self):
        self.wipe()
