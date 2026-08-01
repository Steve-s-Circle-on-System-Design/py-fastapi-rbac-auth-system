from typing import Annotated

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
import json
import app.contracts as contracts
from app.auth import create_new_user, login, logout, refresh_token
from app.database import get_db
from app.security import verify_email_provider_webhook
from app.services.email_service import EmailStatusService, WebhookPayload


router = APIRouter(prefix="/webhooks/emails", tags=["Webhooks"])

@router.post(
    "/users",
    response_model=contracts.UserRead,
    status_code=status.HTTP_201_CREATED,
    tags=["User Creation"],
)
async def create_user(
    user: contracts.UserCreate, db: Annotated[AsyncSession, Depends(get_db)]
):
    return await create_new_user(db, user)


@router.post("/auth/login", response_model=contracts.TokenPair, tags=["Authentication"])
async def login_user(
    credentials: contracts.LoginRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await login(db, credentials, request)


@router.post(
    "/auth/refresh", response_model=contracts.TokenPair, tags=["Authentication"]
)
async def refresh_user_token(
    payload: contracts.RefreshTokenRequest,
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    return await refresh_token(db, payload.refresh_token, request)


@router.post(
    "/auth/logout", status_code=status.HTTP_204_NO_CONTENT, tags=["Authentication"]
)
async def logout_user(
    payload: contracts.RefreshTokenRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
) -> Response:
    await logout(db, payload.refresh_token)
    return Response(status_code=status.HTTP_204_NO_CONTENT)

@router.post("/events", status_code=status.HTTP_200_OK)
async def email_events_webhook(
    raw_body: bytes = Depends(verify_email_provider_webhook),
):
    """
    Endpoint protected by the Webhook Security Guard dependency.
    Parses payload and runs state-machine evaluation rules.
    """
    try:
        data = json.loads(raw_body.decode("utf-8"))
        payload = WebhookPayload(**data)
    except Exception as e:
        return {"status": "error", "detail": f"Invalid payload structure: {str(e)}"}

    return {"status": "success", "processed_event": payload.event_type}
