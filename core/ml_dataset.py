"""
Builds a labeled training dataset for the ML risk classifier WITHOUT any
human manually labeling examples by hand. Instead, we generate a large
number of realistic example commands, and label each one automatically
using our EXISTING hardcoded rules (risk_classifier.py).

This technique is called "weak supervision" — trusted rules generate the
labels, so a model can be trained to generalize beyond those exact rules
to commands it has never seen.
"""
import csv
import os
import sys

sys.path.append(os.path.join(os.path.dirname(__file__), ".."))
from core.risk_classifier import classify_by_rules, classify_git_op

OUTPUT_PATH = os.path.join(os.path.dirname(__file__), "..", "storage", "training_data.csv")

FILE_NAMES = ["notes.txt", "app.py", "index.html", "data.csv", "config.yaml",
              "report.docx", "utils.py", "styles.css", "readme.md", "server.js"]
FOLDER_NAMES = ["build/", "dist/", "temp/", "logs/", "node_modules/", "cache/",
                "src/", "assets/", "old_backups/"]
BRANCH_NAMES = ["main", "master", "production", "feature-login", "dev",
                "bugfix-123", "release-v2", "staging"]


def generate_shell_commands():
    examples = []
    for f in FILE_NAMES:
        examples.append(f"cat {f}")
        examples.append(f"echo Processing {f}")
        examples.append(f"ls -la")
        examples.append(f"python {f}")
        examples.append(f"npm install")
        examples.append(f"pip install requests")

    for f in FILE_NAMES:
        examples.append(f"rm {f}")
        examples.append(f"mv {f} backup_{f}")

    for folder in FOLDER_NAMES:
        examples.append(f"rm -rf {folder}")
    examples.append("chmod 777 server.js")
    examples.append("sudo rm -rf /")
    examples.append("echo data > /dev/sda")

    for f in EXTRA_FILES:
        examples.append(f"cat {f}")
        examples.append(f"echo checking {f}")
        examples.append(f"rm {f}")
        examples.append(f"mv {f} archive_{f}")
        examples.append(f"chmod 777 {f}")
    for folder in EXTRA_FOLDERS:
        examples.append(f"rm -rf {folder}")
        examples.append(f"sudo rm -rf {folder}")
        examples.append(f"ls {folder}")
        examples.append(f"mv {folder} old_{folder}")
    examples.append("drop table users")
    examples.append("psql -c 'drop table orders'")

    return examples


def generate_git_commands():
    examples = []
    for branch in BRANCH_NAMES:
        examples.append(f"git commit -m \"update {branch}\"")
        examples.append(f"git status")
        examples.append(f"git log")
        examples.append(f"git pull origin {branch}")
        examples.append(f"git push origin {branch}")
        examples.append(f"git push --force origin {branch}")
        examples.append(f"git branch -d {branch}")
        examples.append(f"git reset --hard {branch}")
    return examples

EXTRA_FILES = ["main.py", "test_app.py", "package.json", "schema.sql", "deploy.sh",
               "database.db", "app.log", "requirements.txt", "setup.py", "Dockerfile"]
EXTRA_FOLDERS = ["tmp/", "output/", "coverage/", "venv/", "__pycache__/", "uploads/"]

# Hand-labeled commands that NO hardcoded rule covers. These teach the model
# the gap cases. The generator checks each one against the rules and skips
# any that a rule already handles, so rules stay authoritative.
HAND_LABELED = {
    "LOW": [
        "python app.py", "python main.py", "python -m pytest", "pytest tests/ -v",
        "npm run build", "npm test", "npm run dev", "node server.js",
        "head -n 20 app.py", "tail -f logs/app.log", "grep -r TODO src/",
        "wc -l app.py", "find . -name '*.py'", "tree", "touch notes.txt",
        "mkdir build", "cd src", "df -h", "ps aux",
    ],
    "MEDIUM": [
        "pip install requests", "pip install -r requirements.txt", "pip uninstall requests",
        "npm install", "npm install express", "npm uninstall lodash",
        "curl -O https://example.com/file.zip", "wget https://example.com/data.csv",
        "sed -i s/old/new/ app.py", "chmod +x run.sh", "chown user app.py",
        "kill 1234", "pkill node", "docker stop web", "kubectl delete pod web-1",
        "git rebase main", "git merge feature-login", "git stash drop",
        "git checkout -- .",
    ],
    "HIGH": [
        "git clean -fd", "git clean -fdx build/", "chmod -R 777 /var/www",
        "dd if=/dev/zero of=/dev/sda", "mkfs.ext4 /dev/sda1", "shutdown -h now",
        "sudo reboot", "kill -9 -1", "find /var -type f -delete",
        "truncate -s 0 production.db", "docker system prune -af",
        "kubectl delete namespace production", "format c:",
    ],
}

def build_dataset():
    rows = []
    skipped = []

    for cmd in generate_shell_commands():
        label = classify_by_rules(cmd)
        if label is None:
            skipped.append(cmd)
            continue
        rows.append((cmd, label))

    for cmd in generate_git_commands():
        label = classify_git_op(cmd)
        rows.append((cmd, label))
    for label, commands in HAND_LABELED.items():
        for cmd in commands:
            if classify_by_rules(cmd) is not None:
                print(f"Skipping hand-labeled {cmd!r}: a hardcoded rule already covers it")
                continue
            rows.append((cmd, label))
    seen = set()
    unique_rows = []
    for cmd, label in rows:
        if cmd not in seen:
            seen.add(cmd)
            unique_rows.append((cmd, label))

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["command", "risk_tier"])
        writer.writerows(unique_rows)

    if skipped:
        print(f"Skipped {len(set(skipped))} commands no rule covers (e.g. {skipped[0]!r})")
    return unique_rows


if __name__ == "__main__":
    rows = build_dataset()
    print(f"Generated {len(rows)} labeled examples -> {OUTPUT_PATH}")

    from collections import Counter
    counts = Counter(label for _, label in rows)
    print("Label distribution:", dict(counts))