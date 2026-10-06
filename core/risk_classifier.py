import sys
import os
import re

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.ml_classifier import predict_risk

HIGH_RISK_PATTERNS = ["rm -rf", "git push --force", "git reset --hard",
                       "drop table", "chmod 777", "> /dev/"]
MEDIUM_RISK_PATTERNS = ["rm ", "git push", "git reset", "mv ", "git branch -d"]
PROTECTED_BRANCHES = ["main", "master", "production"]

# Read-only commands with no side effects. Matched as whole words only
# ("ls" matches "ls -la" but not "lsblk"), and never if the command contains
# a redirect or substitution that could hide a write.
DEFINITELY_SAFE_PREFIXES = [
    "ls", "pwd", "whoami", "date", "cat", "echo", "which",
    "python --version", "python3 --version", "node --version", "npm --version",
    "pip list", "pip show", "npm list",
]

CHAIN_OPERATORS = r"&&|\|\||;|\|"
RISK_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
SHELL_PIPE_RE = re.compile(r"\|\s*(sudo\s+)?(ba|z|da|k)?sh\b")
SYSTEM_REDIRECT_RE = re.compile(r">>?\s*/(etc|boot|usr|bin|sbin|sys|proc|lib)/")


def _pipes_into_shell(command: str) -> bool:
    """curl x | bash and friends. Must be checked BEFORE chain-splitting,
    because splitting on the pipe hides the danger."""
    return bool(SHELL_PIPE_RE.search(command.lower()))


def _is_recursive_force_rm(cmd_lower: str) -> bool:
    """rm with both a recursive and a force flag, in any order or spelling
    (-rf, -fr, -r -f, --recursive --force)."""
    tokens = cmd_lower.split()
    if "rm" not in tokens:
        return False
    args = tokens[tokens.index("rm") + 1:]
    short = "".join(t[1:] for t in args if t.startswith("-") and not t.startswith("--"))
    recursive = "r" in short or "--recursive" in args
    force = "f" in short or "--force" in args
    return recursive and force


def _split_chained_commands(command: str):
    """Splits on shell chaining operators so each part is judged separately;
    a command is only as safe as its riskiest part."""
    parts = re.split(CHAIN_OPERATORS, command)
    return [p.strip() for p in parts if p.strip()]


def _is_definitely_safe(cmd_lower: str) -> bool:
    if any(tok in cmd_lower for tok in (">", "<", "$(", "`")):
        return False
    for p in DEFINITELY_SAFE_PREFIXES:
        if cmd_lower == p or cmd_lower.startswith(p + " "):
            return True
    return False


def classify_by_rules(command: str):
    """Returns LOW/MEDIUM/HIGH if a hardcoded rule matches, else None.
    Never touches the ML model, so it is safe to use for labeling data."""
    cmd_lower = command.lower().strip()
    if any(p in cmd_lower for p in HIGH_RISK_PATTERNS):
        return "HIGH"
    if _is_recursive_force_rm(cmd_lower) or SYSTEM_REDIRECT_RE.search(cmd_lower):
        return "HIGH"
    if _is_definitely_safe(cmd_lower):
        return "LOW"
    if any(p in cmd_lower for p in MEDIUM_RISK_PATTERNS):
        return "MEDIUM"
    return None


def classify_risk(command: str) -> str:
    """
    1. Chained commands: each part is classified separately, highest tier wins.
    2. Hardcoded rules (HIGH patterns, safe allowlist, MEDIUM patterns) are
       authoritative.
    3. Only if no rule matches does the trained ML model decide.
    """
    if _pipes_into_shell(command):
        return "HIGH"
    parts = _split_chained_commands(command)
    if len(parts) > 1:
        tiers = [classify_git_op(p) if p.lower().startswith("git ") else classify_risk(p)
                 for p in parts]
        return max(tiers, key=lambda t: RISK_ORDER[t])

    tier = classify_by_rules(command)
    if tier is not None:
        return tier

    tier, confidence, source = predict_risk(command)
    return tier


def classify_file_op(op_type: str, path: str) -> str:
    path_lower = path.lower()
    if op_type == "delete":
        if ".git" in path_lower or path_lower.startswith("/") or ".." in path_lower:
            return "HIGH"
        return "MEDIUM"
    if op_type == "move":
        return "MEDIUM"
    if op_type in ("create", "write"):
        sensitive_names = [".env", "secret", "credentials", "config"]
        if any(name in path_lower for name in sensitive_names):
            return "MEDIUM"
        return "LOW"
    return "LOW"


def classify_git_op(git_command: str) -> str:
    """Same chained-command handling as classify_risk. Hardcoded subcommand
    rules are authoritative; an unrecognized subcommand falls back to the
    trained model instead of a flat MEDIUM."""
    if _pipes_into_shell(git_command):
        return "HIGH"
    parts = _split_chained_commands(git_command)
    if len(parts) > 1:
        tiers = [classify_git_op(p) if p.lower().startswith("git ") else classify_risk(p)
                 for p in parts]
        return max(tiers, key=lambda t: RISK_ORDER[t])

    cmd = git_command.lower().strip()
    tokens = cmd.split()
    if len(tokens) < 2 or tokens[0] != "git":
        return classify_risk(git_command)
    subcommand = tokens[1]

    if subcommand == "push" and ("--force" in cmd or "-f" in tokens):
        return "HIGH"
    if subcommand == "reset" and "--hard" in cmd:
        return "HIGH"
    if subcommand == "push":
        for branch in PROTECTED_BRANCHES:
            if branch in cmd:
                return "HIGH"
        return "MEDIUM"
    if subcommand in ("branch", "tag") and ("-d" in tokens or "-D" in tokens or "--delete" in cmd):
        for branch in PROTECTED_BRANCHES:
            if branch in cmd:
                return "HIGH"
        return "MEDIUM"
    if subcommand in ("commit", "status", "log", "diff", "pull", "fetch", "add"):
        return "LOW"

    tier, confidence, source = predict_risk(git_command)
    return tier


if __name__ == "__main__":
    tests = [
        ("git push --force origin main", classify_git_op),
        ("git commit -m 'update'", classify_git_op),
        ("git branch -d main", classify_git_op),
        ("git push origin feature-branch", classify_git_op),
        ("echo data > /dev/sda", classify_risk),
    ]
    for cmd, fn in tests:
        print(f"{cmd!r:45} -> {fn(cmd)}")