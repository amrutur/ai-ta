"""
Tests for storage_utils — GCS upload and signed URL generation.
"""

import datetime
from unittest.mock import MagicMock, patch

from storage_utils import generate_signed_upload_url, upload_blob


class TestUploadBlob:
    @patch("storage_utils._get_storage_client")
    def test_upload_returns_gs_uri(self, mock_client_fn):
        mock_client = MagicMock()
        mock_client_fn.return_value = mock_client
        mock_blob = MagicMock()
        mock_client.bucket.return_value.blob.return_value = mock_blob

        uri = upload_blob("my-bucket", "course/file.pdf", b"data", content_type="application/pdf")

        assert uri == "gs://my-bucket/course/file.pdf"
        mock_blob.upload_from_string.assert_called_once_with(b"data", content_type="application/pdf")

    @patch("storage_utils._get_storage_client")
    def test_upload_no_content_type(self, mock_client_fn):
        mock_client = MagicMock()
        mock_client_fn.return_value = mock_client
        mock_blob = MagicMock()
        mock_client.bucket.return_value.blob.return_value = mock_blob

        uri = upload_blob("bucket", "path/to/file.txt", b"hello")

        assert uri == "gs://bucket/path/to/file.txt"
        mock_blob.upload_from_string.assert_called_once_with(b"hello", content_type=None)


class TestGenerateSignedUploadUrl:
    @patch("storage_utils._get_credentials")
    @patch("storage_utils._get_storage_client")
    def test_returns_signed_url(self, mock_client_fn, mock_creds_fn):
        mock_client = MagicMock()
        mock_client_fn.return_value = mock_client
        mock_blob = MagicMock()
        mock_blob.generate_signed_url.return_value = "https://storage.googleapis.com/signed-url"
        mock_client.bucket.return_value.blob.return_value = mock_blob

        url = generate_signed_upload_url("bucket", "path/file.pdf", "application/pdf")

        assert url == "https://storage.googleapis.com/signed-url"
        mock_blob.generate_signed_url.assert_called_once()
        call_kwargs = mock_blob.generate_signed_url.call_args[1]
        assert call_kwargs["method"] == "PUT"
        assert call_kwargs["content_type"] == "application/pdf"
        assert call_kwargs["version"] == "v4"

    @patch("storage_utils._get_credentials")
    @patch("storage_utils._get_storage_client")
    def test_custom_expiration(self, mock_client_fn, mock_creds_fn):
        mock_client = MagicMock()
        mock_client_fn.return_value = mock_client
        mock_blob = MagicMock()
        mock_blob.generate_signed_url.return_value = "https://signed-url"
        mock_client.bucket.return_value.blob.return_value = mock_blob

        generate_signed_upload_url("bucket", "path/f.pdf", "application/pdf", expiration_minutes=30)

        call_kwargs = mock_blob.generate_signed_url.call_args[1]
        assert call_kwargs["expiration"] == datetime.timedelta(minutes=30)
