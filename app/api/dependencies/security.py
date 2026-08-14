import hmac
import hashlib
import os
from fastapi import Request, HTTPException, status

WEBHOOK_SECRET_KEY = os.getenv("EMAIL_WEBHOOK_SECRET")
SIGNATURE_HEADER = "X-Webhook-Signature"

async def verify_email_provider_webhook(request: Request) -> bytes:
    """
    Dependency to safeguard webhook endpoints by checking cryptographic headers
    against the raw payload body.
    """
    signature = request.headers.get(SIGNATURE_HEADER)
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing cryptographic signature header."
        )

    body_bytes = await request.body()

    computed_signature = hmac.new(
        key=WEBHOOK_SECRET_KEY.encode("utf-8"),
        msg=body_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(computed_signature, signature):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid cryptographic signature."
        )

    return body_bytes
