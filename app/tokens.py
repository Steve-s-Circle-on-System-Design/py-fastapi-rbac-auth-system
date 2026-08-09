import uuid
from datetime import UTC, datetime, timedelta

import jwt
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.models import (
    EmailLog,
    EmailStatusEnum,
    VerificationToken,
    VerificationTokenType,
)


def generate_token(user_id: uuid.UUID, token_type: str = "email_verification") -> str:
    """Generate a signed PyJWT token with jti claim."""
    now = datetime.now(UTC)
    payload = {
        "sub": str(user_id),
        "type": token_type,
        "jti": str(uuid.uuid4()),
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=24)).timestamp()),
    }
    return jwt.encode(
        payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )


def validate_token(token: str, expected_type: str = "email_verification") -> dict:
    """Validate and decode a PyJWT token."""
    try:
        payload = jwt.decode(
            token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        if payload.get("type") != expected_type:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid token type",
            )
        return payload
    except jwt.PyJWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired token",
        ) from exc


async def get_last_verification_token(
    db: AsyncSession, user_id: uuid.UUID
) -> VerificationToken | None:
    """Get the most recent verification token for a user."""
    query = (
        select(VerificationToken)
        .where(
            VerificationToken.user_id == user_id,
            VerificationToken.type == VerificationTokenType.email_verification,
        )
        .order_by(VerificationToken.created_at.desc())
    )
    result = await db.execute(query)
    return result.scalars().first()


async def send_email_verification(
    email: str, token: str, user_id: uuid.UUID, db: AsyncSession
) -> None:
    """Persist verification token and email log entry."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=24)

    # 1. Create database record for verification token
    verification_token = VerificationToken(
        user_id=user_id,
        token=token,
        type=VerificationTokenType.email_verification,
        expires_at=expires_at,
        created_at=now,
    )
    db.add(verification_token)

    # 2. Create EmailLog entry
    email_log = EmailLog(
        user_id=user_id,
        recipient=email,
        subject="Email Verification Token",
        status=EmailStatusEnum.pending,
        created_at=now,
    )
    db.add(email_log)

    # Update status to sent
    email_log.update_status(EmailStatusEnum.sent)
