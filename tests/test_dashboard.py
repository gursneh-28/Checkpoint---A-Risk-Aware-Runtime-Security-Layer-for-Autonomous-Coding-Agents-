import pytest
import os
import sys

# Ensure we can import from the project root
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

from dashboard.app import app
import storage.db

@pytest.fixture
def client(tmp_path, monkeypatch):
    # Set DB_PATH to a temporary file to avoid modifying the real database
    db_file = tmp_path / "test_checkpoint.db"
    monkeypatch.setattr(storage.db, "DB_PATH", str(db_file))
    storage.db.init_db()
    
    app.config["TESTING"] = True
    
    with app.test_client() as client:
        yield client

def create_pending_action():
    return storage.db.log_pending_action("file", "test action", "MEDIUM")

def set_csrf_token(client, token="test_token_123"):
    with client.session_transaction() as sess:
        sess["csrf_token"] = token
    return token

def test_get_resolve_returns_405(client):
    action_id = create_pending_action()
    response = client.get(f"/resolve/{action_id}/approve")
    assert response.status_code == 405
    assert storage.db.get_action_status(action_id) == "pending"

def test_post_resolve_no_token_returns_403(client):
    action_id = create_pending_action()
    set_csrf_token(client, "valid_token")
    # Post without csrf_token in the form data
    response = client.post(f"/resolve/{action_id}/approve")
    assert response.status_code == 403
    assert storage.db.get_action_status(action_id) == "pending"

def test_post_resolve_wrong_token_returns_403(client):
    action_id = create_pending_action()
    set_csrf_token(client, "valid_token")
    response = client.post(f"/resolve/{action_id}/approve", data={"csrf_token": "wrong_token"})
    assert response.status_code == 403
    assert storage.db.get_action_status(action_id) == "pending"

def test_post_resolve_correct_token_redirects_and_approves(client):
    action_id = create_pending_action()
    token = set_csrf_token(client, "valid_token")
    response = client.post(f"/resolve/{action_id}/approve", data={"csrf_token": token})
    assert response.status_code == 302
    assert storage.db.get_action_status(action_id) == "approved"

def test_post_reject_already_approved_action(client):
    action_id = create_pending_action()
    token = set_csrf_token(client, "valid_token")
    
    # Approve first
    client.post(f"/resolve/{action_id}/approve", data={"csrf_token": token})
    assert storage.db.get_action_status(action_id) == "approved"
    
    # Try to reject it afterwards
    client.post(f"/resolve/{action_id}/reject", data={"csrf_token": token})
    # Status should remain approved
    assert storage.db.get_action_status(action_id) == "approved"

def test_post_resolve_invalid_decision_returns_400(client):
    action_id = create_pending_action()
    token = set_csrf_token(client, "valid_token")
    response = client.post(f"/resolve/{action_id}/banana", data={"csrf_token": token})
    assert response.status_code == 400

def test_get_rollback_returns_405(client):
    response = client.get("/rollback/1")
    assert response.status_code == 405

def test_get_dashboard_contains_csrf_token(client):
    create_pending_action()
    response = client.get("/")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert 'name="csrf_token"' in html
    assert 'type="hidden"' in html
