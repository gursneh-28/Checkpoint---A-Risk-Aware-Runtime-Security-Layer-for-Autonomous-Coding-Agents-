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