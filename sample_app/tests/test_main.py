import pytest
from fastapi.testclient import TestClient
from sample_app.main import app, notes

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_notes():
    """Reset in-memory store before each test."""
    notes.clear()
    yield
    notes.clear()


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_create_note():
    response = client.post("/notes", json={"title": "Test", "content": "Hello"})
    assert response.status_code == 201
    data = response.json()
    assert data["title"] == "Test"
    assert data["content"] == "Hello"
    assert "id" in data


def test_list_notes():
    client.post("/notes", json={"title": "A", "content": "first"})
    client.post("/notes", json={"title": "B", "content": "second"})
    response = client.get("/notes")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_get_note():
    created = client.post("/notes", json={"title": "Find me", "content": "here"}).json()
    response = client.get(f"/notes/{created['id']}")
    assert response.status_code == 200
    assert response.json()["title"] == "Find me"


def test_get_note_not_found():
    response = client.get("/notes/nonexistent-id")
    assert response.status_code == 404


def test_delete_note():
    created = client.post("/notes", json={"title": "Bye", "content": "gone"}).json()
    response = client.delete(f"/notes/{created['id']}")
    assert response.status_code == 204
    assert client.get(f"/notes/{created['id']}").status_code == 404


def test_delete_note_not_found():
    response = client.delete("/notes/nonexistent-id")
    assert response.status_code == 404
