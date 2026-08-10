from datetime import UTC, datetime

import pytest

from app.models import (
    AuditLog,
    EmailLog,
    EmailStatusEnum,
    File,
    FileContextEnum,
    Permission,
    RefreshToken,
    RevokeReasonEnum,
    Role,
    User,
    UserRole,
    VerificationToken,
    VerificationTokenType,
)


def test_enum_values():
    assert EmailStatusEnum.pending.value == "pending"
    assert RevokeReasonEnum.token_reuse.value == "token_reuse"
    assert VerificationTokenType.email_verification.value == "email_verification"
    assert FileContextEnum.profile_picture.value == "profile_picture"


def test_table_names():
    assert User.__tablename__ == "users"
    assert Role.__tablename__ == "roles"
    assert Permission.__tablename__ == "permissions"
    assert RefreshToken.__tablename__ == "refresh_tokens"
    assert EmailLog.__tablename__ == "email_logs"
    assert AuditLog.__tablename__ == "audit_logs"
    assert File.__tablename__ == "files"
    assert VerificationToken.__tablename__ == "verification_token"
    assert UserRole.__tablename__ == "user_roles"


@pytest.mark.asyncio
async def test_user_model_creation(db_session):
    user = User(email="a@example.com", password_hash="hashed")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    assert user.email == "a@example.com"
    assert user.password_hash == "hashed"
    assert user.login_attempts == 0
    assert user.id is not None


@pytest.mark.asyncio
async def test_refresh_token_revoke_sets_reason_and_timestamp(db_session):
    user = User(email="revoke@example.com", password_hash="hashed")
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    token = RefreshToken(
        user_id=user.id,
        token_hash="x" * 64,
        token_family="family",
        expires_at=datetime.now(UTC),
    )
    db_session.add(token)
    await db_session.commit()
    await db_session.refresh(token)
    assert token.is_revoked is False
    token.revoke(RevokeReasonEnum.logout)
    assert token.is_revoked is True
    assert token.revoke_reason == RevokeReasonEnum.logout
    assert token.revoked_at is not None


@pytest.mark.parametrize(
    ("current", "next_"),
    [
        (EmailStatusEnum.pending, EmailStatusEnum.sent),
        (EmailStatusEnum.pending, EmailStatusEnum.failed),
        (EmailStatusEnum.sent, EmailStatusEnum.delivered),
        (EmailStatusEnum.sent, EmailStatusEnum.bounced),
        (EmailStatusEnum.delivered, EmailStatusEnum.opened),
    ],
)
def test_email_log_valid_transitions(current, next_):
    log = EmailLog(recipient="a@example.com", subject="Hi", status=current)
    log.update_status(next_)
    assert log.status == next_


@pytest.mark.parametrize(
    ("current", "next_"),
    [
        (EmailStatusEnum.pending, EmailStatusEnum.delivered),
        (EmailStatusEnum.sent, EmailStatusEnum.opened),
        (EmailStatusEnum.failed, EmailStatusEnum.pending),
        (EmailStatusEnum.opened, EmailStatusEnum.sent),
    ],
)
def test_email_log_invalid_transitions_raise(current, next_):
    log = EmailLog(recipient="a@example.com", subject="Hi", status=current)
    with pytest.raises(ValueError):
        log.update_status(next_)


def test_email_log_records_error_message():
    log = EmailLog(
        recipient="a@example.com",
        subject="Hi",
        status=EmailStatusEnum.pending,
    )
    log.update_status(EmailStatusEnum.failed, "smtp down")
    assert log.status == EmailStatusEnum.failed
    assert log.error_message == "smtp down"
