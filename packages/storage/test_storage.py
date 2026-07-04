"""Tests for the storage bounded context: LocalFilesystemObjectStore and S3ObjectStore mock fallback."""

import os
import tempfile
import pytest
from unittest.mock import patch, MagicMock

from packages.storage.interfaces import ObjectStore
from packages.storage.adapters import LocalFilesystemObjectStore, S3ObjectStore


# ---------------------------------------------------------------------------
# LocalFilesystemObjectStore
# ---------------------------------------------------------------------------

class TestLocalFilesystemObjectStore:
    @pytest.fixture
    def store(self):
        """Provide a LocalFilesystemObjectStore backed by a temp directory in workspace."""
        temp_dir = tempfile.TemporaryDirectory(dir=".")
        store = LocalFilesystemObjectStore(base_dir=temp_dir.name)
        yield store
        temp_dir.cleanup()

    @pytest.mark.asyncio
    async def test_put_and_get(self, store):
        """put() then get() should return the same data."""
        data = b"hello sentinel"
        uri = await store.put("test-key", data)
        assert "test-key" in uri

        result = await store.get("test-key")
        assert result == data

    @pytest.mark.asyncio
    async def test_put_returns_file_uri(self, store):
        """put() should return a file:// URI."""
        uri = await store.put("my-file.bin", b"data")
        assert uri.startswith("file://")

    @pytest.mark.asyncio
    async def test_get_nonexistent_raises(self, store):
        """get() for a key that doesn't exist should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            await store.get("nonexistent-key")

    @pytest.mark.asyncio
    async def test_delete_removes_file(self, store):
        """delete() should remove the file so get() fails afterwards."""
        await store.put("to-delete", b"bye")
        await store.delete("to-delete")

        with pytest.raises(FileNotFoundError):
            await store.get("to-delete")

    @pytest.mark.asyncio
    async def test_delete_nonexistent_is_noop(self, store):
        """Deleting a key that doesn't exist should not raise."""
        await store.delete("never-existed")  # Should not raise

    @pytest.mark.asyncio
    async def test_put_large_binary(self, store):
        """Verify large payloads survive the put/get roundtrip."""
        big_data = os.urandom(1024 * 1024)  # 1 MB
        await store.put("big-file", big_data)
        result = await store.get("big-file")
        assert result == big_data

    @pytest.mark.asyncio
    async def test_put_nested_key(self, store):
        """Keys with path separators should create subdirectories."""
        data = b"nested"
        await store.put("reports/2026/scan.bin", data)
        result = await store.get("reports/2026/scan.bin")
        assert result == data


# ---------------------------------------------------------------------------
# S3ObjectStore mock fallback (no boto3)
# ---------------------------------------------------------------------------

class TestS3ObjectStoreMockFallback:
    @pytest.fixture
    def store(self):
        """Create an S3ObjectStore with boto3 unavailable (mock fallback mode)."""
        with patch.dict("sys.modules", {"boto3": None}):
            s3 = S3ObjectStore.__new__(S3ObjectStore)
            s3.bucket_name = "test-bucket"
            s3.endpoint_url = None
            s3._available = False
            s3._mock_store = {}
            return s3

    @pytest.mark.asyncio
    async def test_fallback_put_and_get(self, store):
        """In fallback mode, put/get should work via in-memory dict."""
        data = b"fallback-data"
        uri = await store.put("key1", data)
        assert "mock-s3://" in uri
        assert "test-bucket" in uri

        result = await store.get("key1")
        assert result == data

    @pytest.mark.asyncio
    async def test_fallback_get_missing_key_raises(self, store):
        """In fallback mode, get() for a missing key should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            await store.get("missing-key")

    @pytest.mark.asyncio
    async def test_fallback_delete(self, store):
        """In fallback mode, delete should remove the key from the mock store."""
        await store.put("del-key", b"data")
        await store.delete("del-key")

        with pytest.raises(FileNotFoundError):
            await store.get("del-key")

    @pytest.mark.asyncio
    async def test_fallback_delete_missing_is_noop(self, store):
        """Deleting a non-existent key in fallback mode should not raise."""
        await store.delete("nope")  # Should not raise


# ---------------------------------------------------------------------------
# ObjectStore interface contract
# ---------------------------------------------------------------------------

class TestObjectStoreContract:
    def test_object_store_cannot_be_instantiated(self):
        """ObjectStore is abstract and cannot be directly instantiated."""
        with pytest.raises(TypeError):
            ObjectStore()

    def test_local_store_implements_interface(self):
        """LocalFilesystemObjectStore should be a subclass of ObjectStore."""
        store = LocalFilesystemObjectStore(base_dir=".")
        assert isinstance(store, ObjectStore)
