from core.file_ops import intercept_write
from storage.db import get_all_checkpoints, init_db

init_db()

# Create a file with some starting content
with open("my_notes.txt", "w") as f:
    f.write("Version 1\n")

# A few writes — each one should snapshot the file BEFORE changing it
intercept_write("my_notes.txt", "Version 2\n")
intercept_write("my_notes.txt", "Version 3\n")

print("\n=== Current file content ===")
print(open("my_notes.txt").read())

print("=== Checkpoints saved ===")
for c in get_all_checkpoints():
    print(c)