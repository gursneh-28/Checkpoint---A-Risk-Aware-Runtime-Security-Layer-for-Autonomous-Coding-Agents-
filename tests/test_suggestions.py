import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.suggestions import suggest_alternative, move_to_trash


def test_force_push_suggests_force_with_lease():
    s = suggest_alternative("git push --force origin feature-x")
    assert s["kind"] == "command"
    assert s["command"] == "git push --force-with-lease origin feature-x"
    assert s["text"]


def test_short_force_flag_is_also_replaced():
    s = suggest_alternative("git push -f origin dev")
    assert s["command"] == "git push --force-with-lease origin dev"


def test_already_safe_force_with_lease_gets_no_suggestion():
    assert suggest_alternative("git push --force-with-lease origin dev") is None


def test_hard_reset_suggests_stash():
    s = suggest_alternative("git reset --hard HEAD~1")
    assert s["kind"] == "command"
    assert s["command"] == "git stash"


def test_rm_suggests_trash_with_paths():
    s = suggest_alternative("rm notes.txt old.log")
    assert s["kind"] == "trash"
    assert s["paths"] == ["notes.txt", "old.log"]
    assert s["command"] is None


def test_rm_recursive_force_still_suggests_trash_for_the_path():
    s = suggest_alternative("rm -rf build/")
    assert s["kind"] == "trash"
    assert s["paths"] == ["build/"]


# ---- no known safer version: no suggestion ----

def test_no_suggestion_for_unmatched_commands():
    for cmd in ["ls -la", "git push origin main", "git commit -m x",
                "npm install", "chmod 777 server.js", "rm", "git"]:
        assert suggest_alternative(cmd) is None, cmd


def test_chained_commands_get_no_suggestion():
    assert suggest_alternative("git status && git push --force") is None
    assert suggest_alternative("rm a.txt; rm b.txt") is None


# ---- the trash action itself ----

def test_move_to_trash_is_recoverable(tmp_path):
    victim = tmp_path / "important.txt"
    victim.write_text("keep me")
    trash = tmp_path / "trash"

    dest = move_to_trash(str(victim), trash_dir=str(trash))

    assert not victim.exists()
    assert os.path.exists(dest)
    assert open(dest).read() == "keep me"


def test_move_to_trash_handles_same_name_twice(tmp_path):
    trash = tmp_path / "trash"
    for _ in range(2):
        f = tmp_path / "a.txt"
        f.write_text("x")
        move_to_trash(str(f), trash_dir=str(trash))
    assert len(os.listdir(trash)) == 2