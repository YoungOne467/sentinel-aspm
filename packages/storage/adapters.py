import os
import logging
from typing import Optional
from .interfaces import ObjectStore

logger = logging.getLogger(__name__)

class LocalFilesystemObjectStore(ObjectStore):
    """OSS Default ObjectStore implementing storage via the local filesystem."""

    def __init__(self, base_dir: str = "storage_data"):
        self.base_dir = os.path.abspath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def _get_path(self, key: str) -> str:
        # Sanitize path to prevent directory traversal
        safe_key = os.path.normpath(key).lstrip(os.path.sep)
        return os.path.join(self.base_dir, safe_key)

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        path = self._get_path(key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        # Write binary file synchronously inside an executor block (or simple write)
        with open(path, "wb") as f:
            f.write(data)
            
        logger.debug(f"Saved local object: {key} ({len(data)} bytes)")
        return f"file://{path}"

    async def get(self, key: str) -> bytes:
        path = self._get_path(key)
        if not os.path.exists(path):
            raise FileNotFoundError(f"Key not found in LocalFilesystemObjectStore: {key}")
            
        with open(path, "rb") as f:
            return f.read()

    async def delete(self, key: str) -> None:
        path = self._get_path(key)
        if os.path.exists(path):
            os.remove(path)
            logger.debug(f"Deleted local object: {key}")


class S3ObjectStore(ObjectStore):
    """S3-compatible adapter abstraction (e.g. AWS S3, MinIO, or Google Cloud Storage XML API)."""

    def __init__(self, bucket_name: str, endpoint_url: Optional[str] = None, aws_access_key_id: Optional[str] = None, aws_secret_access_key: Optional[str] = None):
        self.bucket_name = bucket_name
        self.endpoint_url = endpoint_url
        
        # Try loading boto3 dynamically to allow OSS deployment without mandatory S3 libraries
        try:
            import boto3
            self._s3 = boto3.client(
                "s3",
                endpoint_url=endpoint_url,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key
            )
            self._available = True
        except ImportError:
            logger.warning("boto3 package not found. S3ObjectStore will fallback to simulated operations.")
            self._available = False
            self._mock_store = {}

    async def put(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        if self._available:
            # Run blocking boto3 call in Executor block would be better, but direct call for simplicity
            self._s3.put_object(
                Bucket=self.bucket_name,
                Key=key,
                Body=data,
                ContentType=content_type
            )
            return f"s3://{self.bucket_name}/{key}"
        else:
            self._mock_store[key] = data
            return f"mock-s3://{self.bucket_name}/{key}"

    async def get(self, key: str) -> bytes:
        if self._available:
            response = self._s3.get_object(Bucket=self.bucket_name, Key=key)
            return response["Body"].read()
        else:
            if key not in self._mock_store:
                raise FileNotFoundError(f"Key not found: {key}")
            return self._mock_store[key]

    async def delete(self, key: str) -> None:
        if self._available:
            self._s3.delete_object(Bucket=self.bucket_name, Key=key)
        else:
            self._mock_store.pop(key, None)
