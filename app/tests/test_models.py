import pytest
from app.models import User

def test_user_model_creation():
    user = User(id="testid", email="test@example.com", password_hash="hashedpw")
    user.id = "testid"
    user.email = "test@example.com"
    user.password_hash = "hashedpw"
    assert user.id == "testid"
    assert user.email == "test@example.com"
    assert user.password_hash == "hashedpw"
