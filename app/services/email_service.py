import logging
from typing import Optional
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.models import EmailStatusEnum

logger = logging.getLogger(__name__)

class WebhookPayload(BaseModel):
    message_id: str = Field(..., description="Unique email tracking identifier")
    event_type: EmailStatusEnum = Field(..., description="The incoming event status transition")
    user_id: Optional[int] = Field(None, description="Associated user ID")

class EmailStatusService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def handle_webhook_event(self, payload: WebhookPayload) -> dict:
        email_record = await self._get_email_record_by_message_id(payload.message_id)
        
        if not email_record:
            logger.warning(f"Ignored out-of-order/unknown webhook for missing message_id: {payload.message_id}")
            return {"status": "ignored", "reason": "message_id_not_found"}

        current_status = EmailStatusEnum(email_record.status)
        target_status = payload.event_type
        if target_status != current_status and not EmailStatusEnum.can_transition(current_status, target_status):
            logger.warning(
                f"Blocked backward/illegal status transition for message {payload.message_id}: "
                f"{current_status} -> {target_status}"
            )
            return {"status": "ignored", "reason": "illegal_state_transition"}

        if target_status == current_status:
            return {"status": "success", "reason": "already_at_target_status"}

        email_record.status = target_status
        self.db.add(email_record)

        if target_status in {EmailStatusEnum.BOUNCED, EmailStatusEnum.COMPLAINT, EmailStatusEnum.FAILED}:
            logger.error(f"Hard failure status '{target_status}' received for user_id {payload.user_id}. Revoking session.")
            await self._invalidate_user_sessions(payload.user_id)

        await self.db.commit()
        return {"status": "success", "new_status": target_status}

    async def _get_email_record_by_message_id(self, message_id: str):
        pass

    async def _invalidate_user_sessions(self, user_id: Optional[int]):
        if not user_id:
            return
        pass