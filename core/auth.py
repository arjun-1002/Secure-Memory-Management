"""
Authentication & 2FA Engine
Provides:
- Argon2id password hashing and verification
- RFC 6238 TOTP two-factor authentication (compatible with Google Authenticator, Bitwarden, etc.)
- QR code image generation for 2FA pairing
- Password policy validation
"""

import re
import pyotp
import qrcode
from io import BytesIO
from PIL import Image
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError

# Argon2id hasher configured with OWASP recommended parameters
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,  # 64 MB
    parallelism=4,
    hash_len=32,
    salt_len=16
)


def hash_password(password: str) -> str:
    """Hashes a password using Argon2id."""
    return _hasher.hash(password)


def verify_password(hash_str: str, password: str) -> bool:
    """Verifies a password against an Argon2id hash in constant time."""
    try:
        return _hasher.verify(hash_str, password)
    except (VerifyMismatchError, InvalidHashError):
        return False


def needs_rehash(hash_str: str) -> bool:
    """Checks if hash needs re-hashing due to parameter updates."""
    try:
        return _hasher.check_needs_rehash(hash_str)
    except Exception:
        return False


def generate_totp_secret() -> str:
    """Generates a random Base32 secret for TOTP (RFC 6238)."""
    return pyotp.random_base32()


def get_totp_uri(username: str, secret: str, issuer: str = "SecureMemoryManager") -> str:
    """Returns the otpauth:// URI for scanning with authenticator apps."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, token: str, valid_window: int = 1) -> bool:
    """
    Verifies a 6-digit TOTP token against the secret.
    valid_window=1 allows +-30 seconds clock drift.
    """
    if not token or not token.strip().isdigit() or len(token.strip()) != 6:
        return False
    totp = pyotp.TOTP(secret)
    return totp.verify(token.strip(), valid_window=valid_window)


def generate_qr_image(uri: str, box_size: int = 6, border: int = 2) -> Image.Image:
    """Generates a PIL Image QR code for the TOTP URI."""
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_M,
        box_size=box_size,
        border=border,
    )
    qr.add_data(uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#0f172a", back_color="#ffffff")
    return img.convert("RGB")


def validate_password_strength(password: str) -> tuple[bool, str]:
    """
    Enforces secure password policy:
    Minimum 8 characters, at least 1 uppercase, 1 lowercase, 1 number, 1 special symbol.
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False, "Password must contain at least one special character."
    return True, "Password meets security requirements."
