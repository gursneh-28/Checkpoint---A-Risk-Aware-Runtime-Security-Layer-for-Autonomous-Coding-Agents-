from core.file_ops import intercept_create, intercept_write, intercept_delete

print("Step 1: creating a test file...")
intercept_create("my_notes.txt", "This is line one.\nThis is line two.\n")

print("\nStep 2: adding more content to it...")
intercept_write("my_notes.txt", "This is line three, just added.\n")

print("\nStep 3: now trying to DELETE it (this should pause and wait for the dashboard)...")
intercept_delete("my_notes.txt")

print("\nDone.")