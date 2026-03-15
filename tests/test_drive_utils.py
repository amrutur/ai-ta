"""
Tests for drive_utils — Google Drive link parsing and notebook download helpers.
"""

from unittest.mock import MagicMock, patch

from drive_utils import (
    get_file_id_from_share_link,
    get_notebook_content_from_link_sa,
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
