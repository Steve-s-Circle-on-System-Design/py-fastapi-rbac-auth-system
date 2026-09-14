import uuid

import pytest
from pydantic import ValidationError

from app import contracts


def test_user_create_accepts_valid_input():
    user = contracts.UserCreate(email="a@example.com", password="s3cret!")
    assert user.email == "a@example.com"
    assert user.password == "s3cret!"


def test_user_create_rejects_invalid_email():
    with pytest.raises(ValidationError):
        contracts.UserCreate(email="not-an-email", password="s3cret!")


def test_login_request_accepts_valid_input():
    req = contracts.LoginRequest(email="a@example.com", password="s3cret!")
    assert req.email == "a@example.com"


def test_refresh_token_request_accepts_alias():
    req = contracts.RefreshTokenRequest(refreshToken="some-token")
    assert req.refresh_token == "some-token"
    assert req.model_dump(by_alias=True) == {"refreshToken": "some-token"}


def test_token_pair_serializes_with_aliases():
    pair = contracts.TokenPair(access_token="at", refresh_token="rt")
    data = pair.model_dump(by_alias=True)
    assert data == {
        "accessToken": "at",
        "refreshToken": "rt",
        "tokenType": "bearer",
        "expiresIn": 900,
    }


def test_user_read_from_attributes():
    user = contracts.UserRead(id=uuid.uuid4(), email="a@example.com", role="USER")
    assert user.role == "USER"
