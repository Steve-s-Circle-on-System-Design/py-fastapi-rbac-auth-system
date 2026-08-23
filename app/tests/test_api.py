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


def test_create_user_endpoint(client, admin_headers):
    response = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "api@example.com", "password": "s3cret!"},
        headers=admin_headers,
    )
    assert response.status_code == 201
    body = response.json()
    assert body["email"] == "api@example.com"


def test_create_user_duplicate_email_returns_400(client, admin_headers):
    payload = {"email": "dup@example.com", "password": "s3cret!"}
    first_response = client.post(
        f"{settings.API_V1_STR}/users", json=payload, headers=admin_headers
    )
    assert first_response.status_code == 201

    duplicate_response = client.post(
        f"{settings.API_V1_STR}/users", json=payload, headers=admin_headers
    )
    assert duplicate_response.status_code == 400
    assert "already exists" in duplicate_response.json()["detail"]


def test_login_endpoint_returns_token_pair(client, admin_headers):
    client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "login@example.com", "password": "s3cret!"},
        headers=admin_headers,
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


def test_create_user_requires_admin_token(client):
    response = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "anon@example.com", "password": "s3cret!"},
    )
    assert response.status_code == 401


def test_standard_user_cannot_create_users(client, admin_headers):
    client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "regular@example.com", "password": "s3cret!"},
        headers=admin_headers,
    )
    login = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": "regular@example.com", "password": "s3cret!"},
    )
    user_headers = {"Authorization": f"Bearer {login.json()['accessToken']}"}

    response = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": "forbidden@example.com", "password": "s3cret!"},
        headers=user_headers,
    )
    assert response.status_code == 403


def test_admin_can_access_admin_dashboard(client, admin_headers):
    response = client.get(
        f"{settings.API_V1_STR}/admin/dashboard", headers=admin_headers
    )
    assert response.status_code == 200
    assert response.json()["message"] == "Welcome to the admin dashboard"


def _create_user(client: TestClient, admin_headers, email: str) -> None:
    response = client.post(
        f"{settings.API_V1_STR}/users",
        json={"email": email, "password": "s3cret!"},
        headers=admin_headers,
    )
    assert response.status_code == 201


def _login(client: TestClient, email: str, password: str) -> dict:
    response = client.post(
        f"{settings.API_V1_STR}/auth/login",
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    return response.json()


def test_refresh_endpoint_returns_new_token_pair(client, admin_headers):
    _create_user(client, admin_headers, "refresh@example.com")
    tokens = _login(client, "refresh@example.com", "s3cret!")

    response = client.post(
        f"{settings.API_V1_STR}/auth/refresh",
        json={"refreshToken": tokens["refreshToken"]},
    )
    assert response.status_code == 200
    body = response.json()
    assert body["accessToken"]
    assert body["refreshToken"]
    assert body["refreshToken"] != tokens["refreshToken"]


def test_refresh_endpoint_rejects_unknown_token(client):
    response = client.post(
        f"{settings.API_V1_STR}/auth/refresh",
        json={"refreshToken": "definitely-not-a-real-token"},
    )
    assert response.status_code == 401


def test_refresh_endpoint_rejects_reused_token(client, admin_headers):
    _create_user(client, admin_headers, "reuse@example.com")
    tokens = _login(client, "reuse@example.com", "s3cret!")
    client.post(
        f"{settings.API_V1_STR}/auth/refresh",
        json={"refreshToken": tokens["refreshToken"]},
    )

    response = client.post(
        f"{settings.API_V1_STR}/auth/refresh",
        json={"refreshToken": tokens["refreshToken"]},
    )
    assert response.status_code == 401


def test_logout_endpoint_returns_204(client, admin_headers):
    _create_user(client, admin_headers, "logout@example.com")
    tokens = _login(client, "logout@example.com", "s3cret!")

    response = client.post(
        f"{settings.API_V1_STR}/auth/logout",
        json={"refreshToken": tokens["refreshToken"]},
    )
    assert response.status_code == 204


def test_logout_endpoint_rejects_invalid_token(client):
    response = client.post(
        f"{settings.API_V1_STR}/auth/logout",
        json={"refreshToken": "definitely-not-a-real-token"},
    )
    assert response.status_code == 401
