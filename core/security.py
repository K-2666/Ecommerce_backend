
import uuid
import jwt
import hashlib
import secrets

from datetime import datetime, timedelta, timezone
from core.config import settings


def hash_password(password: str):
    salt = secrets.token_bytes(16)

    hashed = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        600000
    )

    return salt.hex() + ":" + hashed.hex()


def verify_password(password: str, hashed_password: str):
    try:
        salt_hex, stored_hash = hashed_password.split(":")
        salt = bytes.fromhex(salt_hex)

        new_hash = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt,
            600000
        )

        return secrets.compare_digest(
            new_hash.hex(),
            stored_hash
        )
    except (ValueError, TypeError):
        return False


def create_token(user_id: int, token_type: str):
    if token_type not in ("access", "refresh"):
        raise ValueError("Invalid token type")

    now = datetime.now(timezone.utc)

    if token_type == "access":
        expires_at = now + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )
    else:
        expires_at = now + timedelta(
            days=settings.REFRESH_TOKEN_EXPIRE_DAYS
        )

    token_id = str(uuid.uuid4())

    payload = {
        "sub": str(user_id),
        "type": token_type,
        "jti": token_id,
        "iat": now,
        "exp": expires_at
    }

    token = jwt.encode(
        payload,
        settings.JWT_SECRET_KEY,
        algorithm=settings.JWT_ALGORITHM
    )

    return token, token_id, expires_at


def decode_token(token: str):
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM]
    )
