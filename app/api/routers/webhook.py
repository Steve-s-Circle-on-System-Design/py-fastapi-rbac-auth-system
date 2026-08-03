from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession
import json
from app.api.dependencies.security import verify_email_provider_webhook
from app.database import get_db
from app.schemas.email import WebhookPayload
from app.services.email_services import EmailStatusService


router = APIRouter()

@router.post("/webhooks/emails/events", status_code=status.HTTP_200_OK, tags=["Webhooks"])
async def email_events_webhook(
    raw_body: bytes = Depends(verify_email_provider_webhook),
    db: AsyncSession = Depends(get_db),
):
    """
    Endpoint protected by the Webhook Security Guard dependency.
    Parses payload and runs state-machine evaluation rules.
    """
    try:
        data = json.loads(raw_body.decode("utf-8"))
        payload = WebhookPayload(**data)
    except (json.JSONDecodeError, ValidationError) as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid payload structure: {str(e)}",
        )

    return await EmailStatusService.handle_webhook_event(payload, db)


