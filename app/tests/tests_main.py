from fastapi.testclient import TestClient

from app.api import app

# 2. Initialize the TestClient (acts like a mock browser)
client = TestClient(app)


def test_read_root():

    response = client.get("/")
    assert response.status_code == 200
    assert response.json() == {"message": "Hello World"}
