import uuid
from alembic.environment import Optional
from pydantic import BaseModel, Field
from typing import Optional
import uuid


from app.models import EmailStatusEnum


class WebhookPayload(BaseModel):
    message_id: str = Field(..., description="Provider message tracking identifier")
    event_type: EmailStatusEnum = Field(..., description="The incoming event status transition")
    user_id: Optional[uuid.UUID] = Field(None, description="Associated user ID")
    error_message: Optional[str] = Field(None, description="Optional error description from provider")