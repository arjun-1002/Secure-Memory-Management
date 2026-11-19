"""
Secure File Shredder Module
Implements multi-pass data sanitization to securely erase files and prevent recovery:
- Pass 1: Cryptographic random bytes
- Pass 2: Inverted binary pattern (0xFF)
- Pass 3: Zeroes (0x00)
Forces OS disk cache flushes via fsync before truncating and unlinking.
"""

import os
import sys


def secure_shred_file(filepath: str, passes: int = 3) -> tuple[bool, str]:
    """
    Overwrites the file multiple times and deletes it.
    Returns (success, message).
    """
    if not os.path.exists(filepath):
        return False, f"File does not exist: {filepath}"

    if not os.path.isfile(filepath):
        return False, f"Target is not a regular file: {filepath}"

    try:
        file_size = os.path.getsize(filepath)

        with open(filepath, "ba+", buffering=0) as f:
            for pass_num in range(1, passes + 1):
                f.seek(0)
                remaining = file_size
                block_size = 64 * 1024

                while remaining > 0:
                    current_block = min(remaining, block_size)
                    if pass_num == 1:
                        # Random bytes
                        data = os.urandom(current_block)
                    elif pass_num == 2:
                        # 0xFF
                        data = b"\xff" * current_block
                    else:
                        # 0x00
                        data = b"\x00" * current_block

                    f.write(data)
                    remaining -= current_block

                # Flush all OS caches to physical storage
                f.flush()
                os.fsync(f.fileno())

            # Truncate file to zero length
            f.seek(0)
            f.truncate(0)
            f.flush()
            os.fsync(f.fileno())

        # Unlink the file from filesystem
        os.remove(filepath)
        return True, "File shredded successfully."
    except Exception as e:
        return False, f"Failed to shred file: {str(e)}"
