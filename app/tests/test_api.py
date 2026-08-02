from fastapi.testclient import TestClient

from app.config import settings
from app.main import app

plain_client = TestClient(app)


def test_docs_page_served():
    response = plain_client.get("/docs")
    assert response.status_code == 200


def test_openapi_contains_expected_paths():
    response = plain_client.get("/openapi.json")
    assert response.status_code == 200
    paths = response.json()["paths"]
    assert f"{settings.API_V1_STR}/users" in paths
    assert f"{settings.API_V1_STR}/auth/login" in paths
    assert f"{settings.API_V1_STR}/auth/refresh" in paths
    assert f"{settings.API_V1_STR}/auth/logout" in paths


def test_unknown_route_returns_404():
    response = plain_client.get(f"{settings.API_V1_STR}/does-not-exist")
    assert response.status_code == 404


def test_create_user_endpoint(client):
    response = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "api@example.com", "password": "s3cret!"},
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "api@example.com"


def test_create_user_duplicate_email_returns_400(client):
    payload = {"email": "dup@example.com", "password": "s3cret!"}
    assert client.post(f"{settings.API_V1_STR}/users", json=payload).status_code == 201
    response = client.post(f"{settings.API_V1_STR}/users", json=payload)
    assert response.status_code == 400


def test_login_endpoint_returns_token_pair(client):
    client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "login@example.com", "password": "s3cret!"},
    )
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "login@example.com", "password": "s3cret!"},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accessToken"]
    assert body["refreshToken"]


def test_login_invalid_credentials_returns_401(client):
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "nobody@example.com", "password": "wrong"},
    )
    assert response.status_code == 401
