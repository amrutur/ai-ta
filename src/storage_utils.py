"""
Google Cloud Storage utilities for uploading course materials.
"""

import asyncio
import datetime
import logging
from google.cloud import storage
from google.oauth2 import service_account

import config

logger = logging.getLogger(__name__)

def _get_credentials():
    """Return service account credentials for GCS operations."""
    return service_account.Credentials.from_service_account_info(
        config.firestore_cred_dict
    )

def _get_storage_client():
    """Create a GCS client using the same service account as Firestore."""
    return storage.Client(credentials=_get_credentials(), project=config.bucket_name.split('-')[0])


def upload_blob(bucket_name: str, destination_path: str, file_data: bytes, content_type: str | None = None) -> str:
    """Upload a file to GCS and return the gs:// URI.

    Args:
        bucket_name: Name of the GCS bucket.
        destination_path: Path within the bucket (e.g. "course_handle/filename.pdf").
        file_data: Raw file bytes.
        content_type: Optional MIME type.

    Returns:
        The gs:// URI of the uploaded blob.
    """
    client = _get_storage_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(destination_path)
    blob.upload_from_string(file_data, content_type=content_type)
    uri = f"gs://{bucket_name}/{destination_path}"
    logger.info(f"Uploaded {destination_path} to {uri}")
    return uri


def generate_signed_upload_url(bucket_name: str, destination_path: str, content_type: str, expiration_minutes: int = 15) -> str:
    """Generate a V4 signed URL for uploading a file directly to GCS.

    Args:
        bucket_name: Name of the GCS bucket.
        destination_path: Object path within the bucket.
        content_type: MIME type the client must use when uploading.
        expiration_minutes: How long the URL stays valid (default 15 min).

    Returns:
        A signed URL string that accepts a PUT request.
    """
    client = _get_storage_client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(destination_path)

    url = blob.generate_signed_url(
        version="v4",
        expiration=datetime.timedelta(minutes=expiration_minutes),
        method="PUT",
        content_type=content_type,
        credentials=_get_credentials(),
    )
    logger.info(f"Generated signed upload URL for {destination_path} (expires in {expiration_minutes}m)")
    return url


async def list_blobs(bucket_name: str, prefix: str) -> list[dict]:
    """List all blobs under a given prefix in a GCS bucket.

    Args:
        bucket_name: Name of the GCS bucket.
        prefix: Object name prefix to filter by (e.g. "course-handle/").

    Returns:
        A list of dicts with name, size, and updated for each blob.
    """
    client = _get_storage_client()
    bucket = client.bucket(bucket_name)
    blobs = await asyncio.to_thread(lambda: list(bucket.list_blobs(prefix=prefix)))
    return [
        {
            "name": blob.name,
            "size": blob.size,
            "updated": blob.updated.isoformat() if blob.updated else None,
        }
        for blob in blobs
    ]
