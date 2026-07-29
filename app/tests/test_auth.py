import jwt
from app.config import settings
from app.auth import create_access_token

def test_create_access_token():
    token = create_access_token("user_id")
    decoded = jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])
    assert decoded["sub"] == "user_id"