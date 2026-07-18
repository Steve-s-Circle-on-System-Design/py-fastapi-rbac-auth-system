# database_model.py
import uuid
import enum
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy import String, Enum
from database import Base # <--- MUST IMPORT FROM YOUR DATABASE FILE

class UserRole(str, enum.Enum):
    USER = "USER"
    ADMIN = "ADMIN"

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(String, unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String, nullable=False)
    
    # CHANGE THIS LINE: Add native_enum=False
    role: Mapped[UserRole] = mapped_column(
        Enum(UserRole, native_enum=False), 
        default=UserRole.USER, 
        nullable=False
    )