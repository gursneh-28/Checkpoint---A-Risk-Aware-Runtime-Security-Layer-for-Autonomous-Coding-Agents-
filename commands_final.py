import json, csv

rows = [json.loads(l) for l in open("commands_filtered.jsonl", encoding="utf-8")]
rows.sort(key=lambda d: (d["repo"], d["file"]))   # group by repo, then file

with open("commands_for_review.csv", "w", newline="", encoding="utf-8-sig") as f:
    w = csv.writer(f)
    w.writerow(["no", "command", "repo", "file", "sir_comment"])
    for i, d in enumerate(rows, 1):
        w.writerow([i, d["command"], d["repo"], d["file"], ""])

print(len(rows), "commands written")