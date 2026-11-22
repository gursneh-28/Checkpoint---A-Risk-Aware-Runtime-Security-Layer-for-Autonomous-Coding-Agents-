import os
import pytest
from core.blob_store import (
    BlobStore, FileTooLargeError, BlobIntegrityError, BlobNotFoundError,
    MAX_FILE_BYTES, EMPTY_SHA256
)


@pytest.fixture
def store(tmp_path):
    store_dir = tmp_path / "blobs"
    return BlobStore(str(store_dir))


def test_put_and_get_bytes(store):
    data = b"Hello, Checkpoint content-addressed storage!"
    info = store.put_bytes(data)
    assert len(info.blob_hash) == 64
    assert info.original_size == len(data)
    assert info.compressed_size > 0

    retrieved = store.get_bytes(info.blob_hash)
    assert retrieved == data


def test_identical_content_deduplicates(store):
    data = b"identical content for deduplication test"
    info1 = store.put_bytes(data)
    info2 = store.put_bytes(data)

    assert info1.blob_hash == info2.blob_hash
    assert info1.compressed_size == info2.compressed_size


def test_empty_file_handling(store):
    data = b""
    info = store.put_bytes(data)
    assert info.blob_hash == EMPTY_SHA256
    assert info.original_size == 0
    assert store.get_bytes(EMPTY_SHA256) == b""


def test_put_file_from_disk(store, tmp_path):
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("file content from disk", encoding="utf-8")

    info = store.put_file(str(sample_file))
    assert store.has_blob(info.blob_hash)
    assert store.get_bytes(info.blob_hash) == b"file content from disk"


def test_file_exceeding_50mb_fails(store):
    # Test with boundary > 50 MB
    large_payload = b"x" * (MAX_FILE_BYTES + 1)
    with pytest.raises(FileTooLargeError):
        store.put_bytes(large_payload)


def test_missing_blob_raises_not_found(store):
    non_existent_hash = "a" * 64
    with pytest.raises(BlobNotFoundError):
        store.get_bytes(non_existent_hash)


def test_corrupt_blob_fails_integrity_check(store):
    data = b"uncompressed valid data"
    info = store.put_bytes(data)

    blob_path = store._blob_path(info.blob_hash)
    assert os.path.exists(blob_path)

    # Corrupt the compressed file on disk
    with open(blob_path, "wb") as f:
        f.write(b"corrupted raw non-zlib bytes that will fail decompression")

    with pytest.raises(BlobIntegrityError):
        store.get_bytes(info.blob_hash)


def test_delete_blob(store):
    data = b"temporary blob"
    info = store.put_bytes(data)
    assert store.has_blob(info.blob_hash)

    assert store.delete_blob(info.blob_hash) is True
    assert store.has_blob(info.blob_hash) is False
    assert store.delete_blob(info.blob_hash) is False
