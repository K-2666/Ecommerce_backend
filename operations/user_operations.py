
from sqlalchemy.orm import Session
from models import User, RefreshToken
from schemas import UserCreate
from core.security import hash_password, create_token, verify_password, decode_token
from datetime import datetime, timezone
import jwt


def register_user(db: Session, user_data: UserCreate):
    existing_user = db.query(User).filter(
        User.email == user_data.email
    ).first()

    if existing_user:
        return None

    new_user = User(
        full_name=user_data.full_name,
        email=user_data.email,
        hashed_password=hash_password(user_data.password)
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return new_user


def login_user(db: Session, email: str, password: str):
    user = db.query(User).filter(
        User.email == email
    ).first()

    if not user:
        return None

    if not verify_password(password, user.hashed_password):
        return None

    if not user.is_active:
        return None

    access_token, access_jti, access_expiry = create_token(
        user.id, "access"
    )

    refresh_token, refresh_jti, refresh_expiry = create_token(
        user.id, "refresh"
    )

    stored_token = RefreshToken(
        user_id=user.id,
        token_jti=refresh_jti,
        expires_at=refresh_expiry
    )

    db.add(stored_token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


def refresh_user_tokens(db: Session, token: str):
    try:
        payload = decode_token(token)

        if payload.get("type") != "refresh":
            return None

        user_id = int(payload.get("sub"))
        token_jti = payload.get("jti")

    except (jwt.InvalidTokenError, ValueError, TypeError):
        return None

    stored_token = db.query(RefreshToken).filter(
        RefreshToken.token_jti == token_jti,
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None)
    ).first()

    if stored_token is None:
        return None

    current_time = datetime.now(timezone.utc).replace(tzinfo=None)

    if stored_token.expires_at <= current_time:
        return None

    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None or not user.is_active:
        return None

    access_token, _, _ = create_token(user.id, "access")
    refresh_token, refresh_jti, refresh_expiry = create_token(
        user.id, "refresh"
    )

    stored_token.revoked_at = current_time

    new_stored_token = RefreshToken(
        user_id=user.id,
        token_jti=refresh_jti,
        expires_at=refresh_expiry
    )

    db.add(new_stored_token)
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


def logout_user(db: Session, token: str):
    try:
        payload = decode_token(token)

        if payload.get("type") != "refresh":
            return False

        user_id = int(payload.get("sub"))
        token_jti = payload.get("jti")

    except (jwt.InvalidTokenError, ValueError, TypeError):
        return False

    stored_token = db.query(RefreshToken).filter(
        RefreshToken.token_jti == token_jti,
        RefreshToken.user_id == user_id,
        RefreshToken.revoked_at.is_(None)
    ).first()

    if stored_token is None:
        return False

    current_time = datetime.now(timezone.utc).replace(tzinfo=None)

    if stored_token.expires_at <= current_time:
        return False

    stored_token.revoked_at = current_time
    db.commit()

    return True


def get_all_users(db: Session, skip: int = 0, limit: int = 10):
    users = db.query(User).offset(skip).limit(limit).all()

    return users


def get_user_by_id(db: Session, user_id: int):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    return user


def update_user(db: Session, user_id: int, user_data):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        return None

    if user_data.email is not None:
        existing_email = db.query(User).filter(
            User.email == user_data.email,
            User.id != user_id
        ).first()

        if existing_email:
            return False

    if user_data.full_name is not None:
        user.full_name = user_data.full_name

    if user_data.email is not None:
        user.email = user_data.email

    if user_data.phone is not None:
        user.phone = user_data.phone

    db.commit()
    db.refresh(user)

    return user


def delete_user(db: Session, user_id: int, current_user_id: int):
    user = db.query(User).filter(
        User.id == user_id
    ).first()

    if user is None:
        return None

    if user.id == current_user_id:
        return False

    db.delete(user)
    db.commit()

    return True


def search_users(db: Session, search_term: str):
    search_value = f"%{search_term}%"

    users = db.query(User).filter(
        (User.full_name.ilike(search_value)) |
        (User.email.ilike(search_value)) |
        (User.phone.ilike(search_value))
    ).all()

    return users
