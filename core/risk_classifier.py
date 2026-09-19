HIGH_RISK_PATTERNS = ["rm -rf", "git push --force", "git reset --hard",
                       "drop table", "chmod 777", "> /dev/"]
MEDIUM_RISK_PATTERNS = ["rm ", "git push", "git reset", "mv ", "git branch -d"]

PROTECTED_BRANCHES = ["main", "master", "production"]


def classify_risk(command: str) -> str:
    """Original shell-command classifier — kept for plain shell commands."""
    cmd_lower = command.lower()
    for pattern in HIGH_RISK_PATTERNS:
        if pattern in cmd_lower:
            return "HIGH"
    for pattern in MEDIUM_RISK_PATTERNS:
        if pattern in cmd_lower:
            return "MEDIUM"
    return "LOW"


def classify_file_op(op_type: str, path: str) -> str:
    """
    Risk tier for a file operation, based on the action type and the path
    it touches. This is deliberately simple for now — later this becomes
    the reversibility x blast-radius x cost scoring model.
    """
    path_lower = path.lower()

    # Deleting or moving something is inherently riskier than creating/writing
    if op_type == "delete":
        if ".git" in path_lower or path_lower.startswith("/") or ".." in path_lower:
            return "HIGH"   # touching git internals or going outside project scope
        return "MEDIUM"

    if op_type == "move":
        return "MEDIUM"

    if op_type in ("create", "write"):
        # Writing to a config/secrets-looking file is riskier than a normal file
        sensitive_names = [".env", "secret", "credentials", "config"]
        if any(name in path_lower for name in sensitive_names):
            return "MEDIUM"
        return "LOW"

    return "LOW"


def classify_git_op(git_command: str) -> str:
    """
    Git-specific classification. Looks at the actual subcommand and target
    branch, not just keyword matching on the whole string.
    """
    cmd = git_command.lower().strip()
    tokens = cmd.split()

    if len(tokens) < 2 or tokens[0] != "git":
        return classify_risk(git_command)  # fallback to generic classifier

    subcommand = tokens[1]

    # Force-push or hard reset are always high risk
    if subcommand == "push" and ("--force" in cmd or "-f" in tokens):
        return "HIGH"
    if subcommand == "reset" and "--hard" in cmd:
        return "HIGH"

    # Pushing directly to a protected branch is high risk
    if subcommand == "push":
        for branch in PROTECTED_BRANCHES:
            if branch in cmd:
                return "HIGH"
        return "MEDIUM"

    # Deleting a branch or tag is medium risk, higher if it's a protected branch
    if subcommand in ("branch", "tag") and ("-d" in tokens or "-D" in tokens or "--delete" in cmd):
        for branch in PROTECTED_BRANCHES:
            if branch in cmd:
                return "HIGH"
        return "MEDIUM"

    # Commit, status, log, diff, pull (without force) — routine, low risk
    if subcommand in ("commit", "status", "log", "diff", "pull", "fetch", "add"):
        return "LOW"

    return "MEDIUM"  # unrecognized git subcommand — be cautious by default


if __name__ == "__main__":
    # Quick manual tests
    tests = [
        ("git push --force origin main", classify_git_op),
        ("git commit -m 'update'", classify_git_op),
        ("git branch -d main", classify_git_op),
        ("git push origin feature-branch", classify_git_op),
    ]
    for cmd, fn in tests:
        print(f"{cmd!r:45} -> {fn(cmd)}")