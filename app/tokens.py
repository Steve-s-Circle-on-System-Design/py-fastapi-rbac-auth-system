import asyncio
import smtplib
import uuid
from datetime import UTC, datetime, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

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
    """Generate a signed PyJWT token with jti claim and 'user' payload key."""
    now = datetime.now(UTC)
    payload = {
        "user": str(user_id),
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


def _send_smtp_email(
    recipient: str, subject: str, text_body: str, html_body: str
) -> None:
    """Synchronous helper to connect to SMTP server and deliver email."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = settings.SMTP_FROM_EMAIL
    msg["To"] = recipient

    msg.attach(MIMEText(text_body, "plain"))
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT, timeout=10) as server:
        if settings.SMTP_TLS:
            server.starttls()
        if settings.SMTP_USER and settings.SMTP_PASSWORD:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
        server.sendmail(settings.SMTP_FROM_EMAIL, [recipient], msg.as_string())


async def send_email_verification(
    email: str,
    token: str,
    user_id: uuid.UUID,
    db: AsyncSession,
    host_url: str | None = None,
) -> None:
    """Persist verification token, construct link, and send via SMTP."""
    now = datetime.now(UTC)
    expires_at = now + timedelta(hours=24)

    # Construct automatic verification URL
    base_url = (host_url or settings.BASE_URL).rstrip("/")
    verification_url = f"{base_url}{settings.API_V1_STR}/auth/verify?token={token}"

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
        subject="Email Verification Link",
        status=EmailStatusEnum.pending,
        created_at=now,
    )
    db.add(email_log)

    # 3. Build email bodies
    text_body = (
        f"Welcome! Please verify your email by clicking the link below:\n\n"
        f"{verification_url}\n\n"
        f"If you did not request this, please ignore this email."
    )
    btn_style = (
        "padding: 10px 20px; background-color: #007bff; "
        "color: white; text-decoration: none; border-radius: 5px;"
    )
    html_body = f"""
    <html>
      <body>
        <h2>Email Verification</h2>
        <p>Welcome! Please verify your email by clicking the button below:</p>
        <p>
          <a href="{verification_url}" style="{btn_style}">
            Verify Email Address
          </a>
        </p>
        <p>Or copy and paste this link into your browser:</p>
        <p><a href="{verification_url}">{verification_url}</a></p>
      </body>
    </html>
    """

    # 4. Attempt SMTP dispatch
    try:
        await asyncio.to_thread(
            _send_smtp_email, email, email_log.subject, text_body, html_body
        )
        email_log.update_status(EmailStatusEnum.sent)
    except Exception as e:
        email_log.update_status(EmailStatusEnum.failed, error_message=str(e))
