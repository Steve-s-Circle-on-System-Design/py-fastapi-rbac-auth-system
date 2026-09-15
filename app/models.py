import enum
import uuid
from datetime import UTC, datetime
from typing import ClassVar

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base

# --- ENUMS ---


class VerificationTokenType(enum.StrEnum):
    email_verification = "email_verification"
    password_reset = "password_reset"


class FileContextEnum(enum.StrEnum):
    profile_picture = "profile_picture"
    uploads = "uploads"


class EmailStatusEnum(enum.StrEnum):
    pending = "pending"
    sent = "sent"
    delivered = "delivered"
    failed = "failed"
    bounced = "bounced"
    opened = "opened"
    complaint = "complaint"


class RevokeReasonEnum(enum.StrEnum):
    logout = "logout"
    logout_all = "logout_all"
    password_change = "password_change"
    token_reuse = "token_reuse"
    account_suspended = "account_suspended"
    session_hijack_suspected = "session_hijack_suspected"
    rotated = "rotated"
    expired = "expired"


# --- ASSOCIATION TABLES / JOIN TABLES ---


class RolePermission(Base):
    __tablename__ = "role_permission"

    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )


class UserRole(Base):
    __tablename__ = "user_roles"

    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    role_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )


class UserFile(Base):
    __tablename__ = "user_files"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    file_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )

    __table_args__ = (UniqueConstraint("user_id", "file_id", name="uq_user_file"),)


# --- ENTITY MODELS ---


class Permission(Base):
    __tablename__ = "permissions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )

    roles: Mapped[list["Role"]] = relationship(
        secondary="role_permission", back_populates="permissions"
    )


class Role(Base):
    __tablename__ = "roles"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )

    permissions: Mapped[list["Permission"]] = relationship(
        secondary="role_permission", back_populates="roles"
    )
    users: Mapped[list["User"]] = relationship(
        secondary="user_roles", back_populates="roles"
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(
        String(255), unique=True, index=True, nullable=False
    )
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    last_login: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_login_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    email_verified_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)

    provider_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    provider: Mapped[str | None] = mapped_column(String(50), nullable=True)
    login_attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    lockout_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    @property
    def failed_login_attempts(self) -> int:
        return self.login_attempts

    @failed_login_attempts.setter
    def failed_login_attempts(self, value: int) -> None:
        self.login_attempts = value

    # fixed datetime conflict issue
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("TIMEZONE('utc', now())"),
        onupdate=lambda: datetime.now(UTC),
    )

    # Relationships
    roles: Mapped[list["Role"]] = relationship(
        secondary="user_roles", back_populates="users"
    )
    files: Mapped[list["File"]] = relationship(
        secondary="user_files", back_populates="users"
    )
    refresh_tokens: Mapped[list["RefreshToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    email_logs: Mapped[list["EmailLog"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    verification_tokens: Mapped[list["VerificationToken"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )
    audit_logs: Mapped[list["AuditLog"]] = relationship(
        back_populates="user", cascade="all, delete-orphan"
    )


class VerificationToken(Base):
    __tablename__ = "verification_token"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    token: Mapped[str] = mapped_column(Text, nullable=False, index=True)
    type: Mapped[VerificationTokenType] = mapped_column(
        Enum(VerificationTokenType, native_enum=False), nullable=False
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_used: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )

    user: Mapped["User"] = relationship(back_populates="verification_tokens")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    resource: Mapped[str] = mapped_column(String(100), nullable=False)
    resource_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    details: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )

    user: Mapped["User"] = relationship(back_populates="audit_logs")


class File(Base):
    __tablename__ = "files"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    file_name: Mapped[str] = mapped_column(String(255), nullable=False)
    context: Mapped[FileContextEnum] = mapped_column(
        Enum(FileContextEnum, native_enum=False), nullable=False
    )
    file_size: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(100), nullable=False)
    cloudinary_public_id: Mapped[str] = mapped_column(String(255), nullable=False)
    secure_url: Mapped[str] = mapped_column(Text, nullable=False)
    format: Mapped[str] = mapped_column(String(50), nullable=False)
    width: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height: Mapped[int | None] = mapped_column(Integer, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    uploaded_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("TIMEZONE('utc', now())"),
        onupdate=lambda: datetime.now(UTC),
    )

    users: Mapped[list["User"]] = relationship(
        secondary="user_files", back_populates="files"
    )


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    # Only a SHA-256 digest is persisted; the opaque token is returned once to
    # the client and cannot be recovered from the database.
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    token_family: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    parent_token_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("refresh_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )

    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)

    revoke_reason: Mapped[RevokeReasonEnum | None] = mapped_column(
        Enum(RevokeReasonEnum, native_enum=False), nullable=True
    )
    revoked_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("TIMEZONE('utc', now())"),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="refresh_tokens")

    parent_token: Mapped["RefreshToken | None"] = relationship(
        "RefreshToken", remote_side=[id], back_populates="child_tokens", uselist=False
    )
    child_tokens: Mapped[list["RefreshToken"]] = relationship(
        "RefreshToken", back_populates="parent_token"
    )

    def revoke(self, reason: RevokeReasonEnum) -> None:
        self.is_revoked = True
        self.revoke_reason = reason
        self.revoked_at = datetime.now(UTC)


class EmailLog(Base):
    __tablename__ = "email_logs"

    TRANSITION_RULES: ClassVar[dict[EmailStatusEnum, set[EmailStatusEnum]]] = {
        EmailStatusEnum.pending: {EmailStatusEnum.sent, EmailStatusEnum.failed},
        EmailStatusEnum.sent: {
            EmailStatusEnum.delivered,
            EmailStatusEnum.bounced,
            EmailStatusEnum.complaint,
        },
        EmailStatusEnum.delivered: {EmailStatusEnum.opened, EmailStatusEnum.complaint},
        EmailStatusEnum.failed: set(),
        EmailStatusEnum.bounced: set(),
        EmailStatusEnum.complaint: set(),
        EmailStatusEnum.opened: set(),
    }

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    recipient: Mapped[str] = mapped_column(String(255), nullable=False)
    subject: Mapped[str] = mapped_column(String(255), nullable=False)

    status: Mapped[EmailStatusEnum] = mapped_column(
        Enum(EmailStatusEnum, native_enum=False),
        default=EmailStatusEnum.pending,
        nullable=False,
    )
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=text("TIMEZONE('utc', now())")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("TIMEZONE('utc', now())"),
        onupdate=lambda: datetime.now(UTC),
        nullable=False,
    )

    user: Mapped["User"] = relationship(back_populates="email_logs")

    def update_status(
        self, new_status: EmailStatusEnum, error_message: str | None = None
    ) -> None:
        allowed_next_states = self.TRANSITION_RULES.get(self.status, set())

        if new_status not in allowed_next_states:
            allowed = [s.value for s in allowed_next_states]
            raise ValueError(
                f"Invalid status transition from '{self.status.value}' "
                f"to '{new_status.value}'. Allowed transitions are: {allowed}"
            )

        self.status = new_status
        if error_message is not None:
            self.error_message = error_message
