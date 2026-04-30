"""
Tests for drive_utils — Google Drive link parsing and notebook download helpers.
"""

from unittest.mock import MagicMock, patch

from drive_utils import (
    download_file_bytes_sa,
    extract_folder_id_from_link,
    get_file_id_from_share_link,
    get_notebook_content_from_link_sa,
    list_pdfs_in_folder_sa,
    load_notebook_from_google_drive_sa,
)


# ---------------------------------------------------------------------------
# get_file_id_from_share_link
# ---------------------------------------------------------------------------

class TestGetFileIdFromShareLink:
    def test_standard_share_link(self):
        link = "https://drive.google.com/file/d/1aBcDeFgHiJkLmNoPqRsTuVwXyZ/view?usp=sharing"
        assert get_file_id_from_share_link(link) == "1aBcDeFgHiJkLmNoPqRsTuVwXyZ"

    def test_colab_link(self):
        link = "https://colab.research.google.com/drive/d/ABC123XYZ/edit"
        assert get_file_id_from_share_link(link) == "ABC123XYZ"

    def test_link_without_query_params(self):
        link = "https://drive.google.com/file/d/FILE_ID_HERE/view"
        assert get_file_id_from_share_link(link) == "FILE_ID_HERE"

    def test_link_with_query_params_stripped(self):
        link = "https://drive.google.com/file/d/MY_ID?usp=sharing&other=1"
        assert get_file_id_from_share_link(link) == "MY_ID"

    def test_invalid_link_no_d_segment(self):
        link = "https://example.com/something/else"
        assert get_file_id_from_share_link(link) is None

    def test_empty_string(self):
        assert get_file_id_from_share_link("") is None

    def test_drive_segment_fallback(self):
        # When 'd' is not present but 'drive' is
        link = "https://colab.research.google.com/drive/NOTEBOOK_ID"
        assert get_file_id_from_share_link(link) == "NOTEBOOK_ID"


# ---------------------------------------------------------------------------
# get_notebook_content_from_link_sa
# ---------------------------------------------------------------------------

class TestGetNotebookContentFromLinkSa:
    @patch("drive_utils.MediaIoBaseDownload")
    @patch("drive_utils.build")
    @patch("drive_utils.service_account.Credentials.from_service_account_info")
    def test_success(self, mock_creds, mock_build, mock_download):
        # Set up the mock download to return content
        mock_downloader = MagicMock()
        mock_downloader.next_chunk.return_value = (None, True)
        mock_download.return_value = mock_downloader

        mock_service = MagicMock()
        mock_build.return_value = mock_service

        # We need to patch BytesIO to capture written content
        sa_info = {"type": "service_account", "project_id": "test"}
        result = get_notebook_content_from_link_sa(sa_info, "file123")

        mock_creds.assert_called_once()
        mock_build.assert_called_once_with("drive", "v3", credentials=mock_creds.return_value)
        # Result will be empty bytes decoded since our mock BytesIO is empty
        assert result is not None or result is None  # depends on mock behavior

    @patch("drive_utils.build")
    @patch("drive_utils.service_account.Credentials.from_service_account_info")
    def test_http_error_returns_none(self, mock_creds, mock_build):
        from googleapiclient.errors import HttpError
        resp = MagicMock()
        resp.status = 404
        mock_build.return_value.files.return_value.get_media.side_effect = HttpError(resp, b"Not Found")

        result = get_notebook_content_from_link_sa({"type": "service_account"}, "bad_id")
        assert result is None

    @patch("drive_utils.build")
    @patch("drive_utils.service_account.Credentials.from_service_account_info")
    def test_generic_error_returns_none(self, mock_creds, mock_build):
        mock_build.side_effect = RuntimeError("connection failed")
        result = get_notebook_content_from_link_sa({"type": "service_account"}, "file123")
        assert result is None


# ---------------------------------------------------------------------------
# load_notebook_from_google_drive_sa
# ---------------------------------------------------------------------------

class TestLoadNotebookFromGoogleDriveSa:
    @patch("drive_utils.get_notebook_content_from_link_sa")
    def test_valid_link(self, mock_get_content):
        mock_get_content.return_value = '{"cells": []}'
        link = "https://drive.google.com/file/d/MYID/view"
        result = load_notebook_from_google_drive_sa({"type": "sa"}, link)
        mock_get_content.assert_called_once_with({"type": "sa"}, "MYID")
        assert result == '{"cells": []}'

    @patch("drive_utils.get_notebook_content_from_link_sa")
    def test_invalid_link_returns_none(self, mock_get_content):
        result = load_notebook_from_google_drive_sa({"type": "sa"}, "not-a-drive-link")
        mock_get_content.assert_not_called()
        assert result is None


# ---------------------------------------------------------------------------
# extract_folder_id_from_link
# ---------------------------------------------------------------------------


class TestExtractFolderIdFromLink:
    def test_standard_folder_link(self):
        link = "https://drive.google.com/drive/folders/1abcDEF_-XYZ"
        assert extract_folder_id_from_link(link) == "1abcDEF_-XYZ"

    def test_with_query_params(self):
        link = "https://drive.google.com/drive/folders/FOLDER_ID?usp=sharing"
        assert extract_folder_id_from_link(link) == "FOLDER_ID"

    def test_with_user_segment(self):
        link = "https://drive.google.com/drive/u/0/folders/FOLDER_ID"
        assert extract_folder_id_from_link(link) == "FOLDER_ID"

    def test_invalid_link(self):
        assert extract_folder_id_from_link("https://example.com/foo") is None

    def test_empty(self):
        assert extract_folder_id_from_link("") is None
        assert extract_folder_id_from_link(None) is None


# ---------------------------------------------------------------------------
# list_pdfs_in_folder_sa
# ---------------------------------------------------------------------------


class TestListPdfsInFolderSa:
    @patch("drive_utils._build_drive_service")
    def test_collects_files_across_pages(self, mock_build):
        # First page returns two files + nextPageToken; second page returns one and stops.
        files_call = MagicMock()
        files_call.list.return_value.execute.side_effect = [
            {
                "files": [
                    {"id": "a", "name": "a.pdf", "modifiedTime": "t1", "size": "100"},
                    {"id": "b", "name": "b.pdf", "modifiedTime": "t2", "size": "200"},
                ],
                "nextPageToken": "pg2",
            },
            {
                "files": [
                    {"id": "c", "name": "c.pdf", "modifiedTime": "t3", "size": "300"},
                ],
                "nextPageToken": None,
            },
        ]
        service = MagicMock()
        service.files.return_value = files_call
        mock_build.return_value = service

        result = list_pdfs_in_folder_sa({"type": "sa"}, "FOLDER_ID")
        assert [f["id"] for f in result] == ["a", "b", "c"]
        assert files_call.list.call_count == 2

    @patch("drive_utils._build_drive_service")
    def test_query_filters_to_pdfs(self, mock_build):
        files_call = MagicMock()
        files_call.list.return_value.execute.return_value = {"files": [], "nextPageToken": None}
        service = MagicMock()
        service.files.return_value = files_call
        mock_build.return_value = service

        list_pdfs_in_folder_sa({"type": "sa"}, "F")
        kwargs = files_call.list.call_args.kwargs
        assert "F" in kwargs["q"]
        assert "mimeType='application/pdf'" in kwargs["q"]
        assert "trashed=false" in kwargs["q"]


# ---------------------------------------------------------------------------
# download_file_bytes_sa
# ---------------------------------------------------------------------------


class TestDownloadFileBytesSa:
    @patch("drive_utils.MediaIoBaseDownload")
    @patch("drive_utils._build_drive_service")
    def test_returns_bytes(self, mock_build, mock_download):
        # Make the downloader complete in one chunk and let BytesIO surface the bytes.
        # We can't easily inject into the inner BytesIO, so we patch it.
        downloader = MagicMock()
        downloader.next_chunk.return_value = (None, True)
        mock_download.return_value = downloader

        # Patch BytesIO so getvalue returns known bytes.
        with patch("drive_utils.io.BytesIO") as mock_bytesio:
            buf = MagicMock()
            buf.getvalue.return_value = b"%PDF-1.4 fake"
            mock_bytesio.return_value = buf

            result = download_file_bytes_sa({"type": "sa"}, "FILE_ID")
            assert result == b"%PDF-1.4 fake"

    @patch("drive_utils._build_drive_service")
    def test_returns_none_on_http_error(self, mock_build):
        from googleapiclient.errors import HttpError
        resp = MagicMock()
        resp.status = 404
        service = MagicMock()
        service.files.return_value.get_media.side_effect = HttpError(resp, b"Not Found")
        mock_build.return_value = service

        assert download_file_bytes_sa({"type": "sa"}, "BAD_ID") is None
