import pytest
import storage.db

def test_decide_action_only_updates_pending(tmp_path, monkeypatch):
    db_path = tmp_path / "checkpoint.db"
    monkeypatch.setattr(storage.db, "DB_PATH", str(db_path))
    
    storage.db.init_db()
    
    # Create a pending action
    action_id = storage.db.log_pending_action("shell", "echo test", "LOW")
    
    # Approve it
    success = storage.db.decide_action(action_id, "approved")
    assert success is True
    assert storage.db.get_action_status(action_id) == "approved"
    
    # Try to reject it now that it's approved
    success_reject = storage.db.decide_action(action_id, "rejected")
    assert success_reject is False
    # Status should stay approved
    assert storage.db.get_action_status(action_id) == "approved"
