"""
Google Cloud Storage utilities for uploading course materials.
"""

import logging
from google.cloud import storage
from google.oauth2 import service_account

import config

logger = logging.getLogger(__name__)

def _get_storage_client():
    """Create a GCS client using the same service account as Firestore."""
    credentials = service_account.Credentials.from_service_account_info(
        config.firestore_cred_dict
    )
    return storage.Client(credentials=credentials, project=config.bucket_name.split('-')[0])


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
