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
