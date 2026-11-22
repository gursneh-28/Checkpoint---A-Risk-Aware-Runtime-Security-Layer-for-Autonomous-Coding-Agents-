"""
Content-addressed blob store for Checkpoint — Feature 7 / Milestone 1.

Features:
- SHA-256 content addressing.
- Transparent zlib compression/decompression.
- Atomic writes: writes to a temporary file on the same volume, then atomic rename.
- Verified writes: checks file integrity immediately after writing.
- 50 MB per-file maximum limit (v2.3 fixed policy).
- Zero-byte files supported with deterministic empty SHA-256 hash.
- Corrupt and missing blob detection with fail-closed errors.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import tempfile
import zlib
from dataclasses import dataclass
from typing import Optional, Tuple

# Fixed v2.3 policy limits
MAX_FILE_BYTES = 50 * 1024 * 1024  # 50 MB
EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


class BlobStoreError(Exception):
    """Base exception for blob store operations."""
    pass


class FileTooLargeError(BlobStoreError):
    """Raised when a file exceeds the 50 MB policy cap."""
    pass


class BlobIntegrityError(BlobStoreError):
    """Raised when blob content does not match its expected SHA-256 hash."""
    pass


class BlobNotFoundError(BlobStoreError):
    """Raised when a requested blob is missing from storage."""
    pass


@dataclass(frozen=True)
class BlobInfo:
    blob_hash: str
    original_size: int
    compressed_size: int


class BlobStore:
    """
    Manages immutable, content-addressed, compressed files on disk.
    Directory structure: store_dir / hash[:2] / hash[2:4] / hash[4:] + '.blob'
    """

    def __init__(self, store_dir: str):
        self.store_dir = os.path.abspath(store_dir)
        self.tmp_dir = os.path.join(self.store_dir, "tmp")
        os.makedirs(self.store_dir, exist_ok=True)
        os.makedirs(self.tmp_dir, exist_ok=True)

    def _blob_path(self, blob_hash: str) -> str:
        """Return the sharded disk path for a blob hash."""
        clean_hash = blob_hash.lower().strip()
        if len(clean_hash) != 64:
            raise ValueError(f"Invalid SHA-256 hash length: {clean_hash}")
        return os.path.join(
            self.store_dir,
            clean_hash[:2],
            clean_hash[2:4],
            f"{clean_hash[4:]}.blob"
        )

    def has_blob(self, blob_hash: str) -> bool:
        """Return True if the blob file exists on disk and is non-empty."""
        path = self._blob_path(blob_hash)
        return os.path.isfile(path) and os.path.getsize(path) > 0

    def put_bytes(self, data: bytes) -> BlobInfo:
        """
        Compress and write bytes to the store under its SHA-256 hash.
        Deduplicates if the blob already exists.
        """
        orig_size = len(data)
        if orig_size > MAX_FILE_BYTES:
            raise FileTooLargeError(
                f"Payload size {orig_size} bytes exceeds maximum allowed 50 MB ({MAX_FILE_BYTES} bytes)"
            )

        blob_hash = hashlib.sha256(data).hexdigest()
        dest_path = self._blob_path(blob_hash)

        # Deduplication: already written and valid
        if self.has_blob(blob_hash):
            return BlobInfo(
                blob_hash=blob_hash,
                original_size=orig_size,
                compressed_size=os.path.getsize(dest_path)
            )

        # Compress content
        compressed = zlib.compress(data, level=6)
        comp_size = len(compressed)

        # Atomic write: write to temp file in self.tmp_dir (guaranteed same filesystem/volume)
        os.makedirs(os.path.dirname(dest_path), exist_ok=True)
        tmp_fd, tmp_path = tempfile.mkstemp(dir=self.tmp_dir, prefix="blob_", suffix=".tmp")
        try:
            with os.fdopen(tmp_fd, "wb") as f:
                f.write(compressed)
                f.flush()
                os.fsync(f.fileno())

            # Atomic rename into destination path
            os.replace(tmp_path, dest_path)
        except Exception:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass
            raise

        # Post-write verification
        verify_data = self.get_bytes(blob_hash)
        if hashlib.sha256(verify_data).hexdigest() != blob_hash:
            try:
                os.remove(dest_path)
            except OSError:
                pass
            raise BlobIntegrityError(f"Verification failed after atomic write of {blob_hash}")

        return BlobInfo(
            blob_hash=blob_hash,
            original_size=orig_size,
            compressed_size=comp_size
        )

    def put_file(self, file_path: str) -> BlobInfo:
        """
        Read a file from disk, verify size limit, and store it.
        Handles zero-byte files safely.
        """
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        file_size = os.path.getsize(file_path)
        if file_size > MAX_FILE_BYTES:
            raise FileTooLargeError(
                f"File '{file_path}' size {file_size} exceeds 50 MB limit"
            )

        with open(file_path, "rb") as f:
            data = f.read()

        return self.put_bytes(data)

    def get_bytes(self, blob_hash: str) -> bytes:
        """
        Read, decompress, and verify the blob data for the given SHA-256 hash.
        Raises BlobNotFoundError if missing, or BlobIntegrityError if corrupt.
        """
        dest_path = self._blob_path(blob_hash)
        if not os.path.isfile(dest_path):
            raise BlobNotFoundError(f"Blob {blob_hash} not found in store")

        try:
            with open(dest_path, "rb") as f:
                compressed = f.read()
        except OSError as e:
            raise BlobStoreError(f"Error reading blob {blob_hash}: {e}")

        try:
            data = zlib.decompress(compressed)
        except Exception as e:
            raise BlobIntegrityError(f"Decompression failed for blob {blob_hash}: {e}")

        actual_hash = hashlib.sha256(data).hexdigest()
        if actual_hash != blob_hash.lower():
            raise BlobIntegrityError(
                f"SHA-256 mismatch for blob {blob_hash}: calculated {actual_hash}"
            )

        return data

    def delete_blob(self, blob_hash: str) -> bool:
        """Delete a blob file from disk. Returns True if removed, False if not found."""
        path = self._blob_path(blob_hash)
        if os.path.isfile(path):
            try:
                os.remove(path)
                return True
            except OSError as e:
                raise BlobStoreError(f"Failed to delete blob {blob_hash}: {e}")
        return False
