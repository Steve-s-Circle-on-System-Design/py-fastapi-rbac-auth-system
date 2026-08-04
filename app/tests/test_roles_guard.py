import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.api import router
from app.roles import Role
from app.security import create_access_token

app = FastAPI()
app.include_router(router)
client = TestClient(app)


def auth_headers(role: Role) -> dict[str, str]:
    token = create_access_token(user_id=uuid.uuid4(), role=role)
    return {"Authorization": f"Bearer {token}"}


def test_admin_can_access_admin_endpoint():
    response = client.get("/admin/dashboard", headers=auth_headers(Role.ADMIN))
    assert response.status_code == 200
    assert response.json()["message"] == "Welcome to the admin dashboard"


def test_standard_user_is_forbidden():
    response = client.get("/admin/dashboard", headers=auth_headers(Role.USER))
    assert response.status_code == 403
    assert (
        response.json()["detail"]
        == "You do not have permission to access this resource."
    )


def test_no_token_is_unauthorized():
    response = client.get("/admin/dashboard")
    assert response.status_code == 401
