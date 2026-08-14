import logging
from typing import Optional
import uuid
from datetime import UTC, datetime
from pydantic import BaseModel, Field
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from app.schemas.email import WebhookPayload
from app.models import EmailLog, EmailStatusEnum, RefreshToken, RevokeReasonEnum

logger = logging.getLogger(__name__)


ALLOWED_TRANSITIONS = {
    "PENDING": ["DELIVERED", "BOUNCED", "COMPLAINT"],
    "DELIVERED": ["COMPLAINT"], 
    "BOUNCED": [],               
    "COMPLAINT": []              
}

class EmailStatusService:
    def __init__(self, db: AsyncSession):
        self.db = db

    async def handle_webhook_event(self, payload: WebhookPayload) -> dict:
        try:
            email_record = await self._get_email_record_by_message_id(payload.message_id)
            
            if not email_record:
                logger.warning(f"Ignored out-of-order/unknown webhook for missing message_id: {payload.message_id}")
                return {"status": "ignored", "reason": "message_id_not_found"}

            current_status = email_record.status
            target_status = payload.event_type

            if target_status == current_status:
                return {"status": "success", "reason": "already_at_target_status"}
            try:
                email_record.update_status(target_status, error_message=payload.error_message)
            except ValueError as e:
                logger.warning(
                    f"Blocked backward/illegal status transition for message {payload.message_id}: "
                    f"{current_status} -> {target_status}. Error: {e}"
                )
                return {"status": "ignored", "reason": "illegal_state_transition"}

            self.db.add(email_record)
            target_user_id = payload.user_id or email_record.user_id
            if target_status in {EmailStatusEnum.BOUNCED, EmailStatusEnum.COMPLAINT, EmailStatusEnum.FAILED}:
                if target_user_id:
                    logger.error(f"Hard failure status '{target_status}' received for user_id {target_user_id}. Revoking sessions.")
                    await self._invalidate_user_sessions(target_user_id)
                else:
                    logger.warning(f"Hard failure status '{target_status}' received for message {payload.message_id}, but no user_id found.")

            await self.db.commit()
            return {"status": "success", "new_status": target_status}

        except Exception as exc:
            await self.db.rollback()
            logger.exception(f"Unexpected error processing webhook for message_id {payload.message_id}: {exc}")
            raise

    async def _get_email_record_by_message_id(self, message_id: str) -> Optional[EmailLog]:
        result = await self.db.execute(
            select(EmailLog)
            .where(EmailLog.message_id == message_id)
            .with_for_update()
        )
        return result.scalars().first()

    async def _invalidate_user_sessions(self, user_id: uuid.UUID):
        now = datetime.now(UTC)
        await self.db.execute(
            update(RefreshToken)
            .where(
                RefreshToken.user_id == user_id,
                RefreshToken.is_revoked.is_(False),
                RefreshToken.revoked_at.is_(None),
            )
            .values(
                is_revoked=True,
                revoked_at=now,
                revoke_reason=RevokeReasonEnum.account_suspended,
            )
        )