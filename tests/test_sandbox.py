import os
import pytest

from storage.db import init_db, get_all_checkpoints
import storage.db
import core.sandbox

def test_snapshot_file_stores_absolute_path(tmp_path, monkeypatch):
    db_path = tmp_path / "checkpoint.db"
    shadow_dir = tmp_path / "shadow"
    
    monkeypatch.setattr(storage.db, "DB_PATH", str(db_path))
    monkeypatch.setattr(core.sandbox, "SHADOW_DIR", str(shadow_dir))
    
    init_db()
    
    monkeypatch.chdir(tmp_path)
    
    test_file_name = "test_rel_file.txt"
    with open(test_file_name, "w") as f:
        f.write("hello world")
        
    core.sandbox.snapshot_file(test_file_name, "test description")
    
    checkpoints = get_all_checkpoints()
    assert len(checkpoints) == 1
    
    stored_file_path = checkpoints[0][2]
    
    assert os.path.isabs(stored_file_path)
    assert stored_file_path == os.path.abspath(test_file_name)


def test_rollback_checkpoint_creates_snapshot_and_logs(tmp_path, monkeypatch):
    db_path = tmp_path / "checkpoint.db"
    shadow_dir = tmp_path / "shadow"
    
    monkeypatch.setattr(storage.db, "DB_PATH", str(db_path))
    monkeypatch.setattr(core.sandbox, "SHADOW_DIR", str(shadow_dir))
    
    storage.db.init_db()
    
    monkeypatch.chdir(tmp_path)
    
    test_file_name = "test_rollback_file.txt"
    with open(test_file_name, "w") as f:
        f.write("original content")
        
    core.sandbox.snapshot_file(test_file_name, "initial snapshot")
    
    checkpoints = storage.db.get_all_checkpoints()
    assert len(checkpoints) == 1
    checkpoint_id = checkpoints[0][0]
    
    with open(test_file_name, "w") as f:
        f.write("modified content")
        
    success, msg = core.sandbox.rollback_checkpoint(checkpoint_id)
    assert success is True
    
    with open(test_file_name, "r") as f:
        content = f.read()
    assert content == "original content"
    
    checkpoints_after = storage.db.get_all_checkpoints()
    assert len(checkpoints_after) == 2
    assert checkpoints_after[0][4] == f"Before rolling back to checkpoint #{checkpoint_id}"
    
    actions = storage.db.get_all_actions()
    assert len(actions) == 1
    assert actions[0][2] == "file"
    assert actions[0][3] == f"ROLLBACK {os.path.abspath(test_file_name)} to checkpoint #{checkpoint_id}"
    assert actions[0][4] == "MEDIUM"
    assert actions[0][5] == "executed"
