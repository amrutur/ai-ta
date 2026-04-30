"""
Google Drive utilities for downloading Colab notebooks and PDF submissions.
"""

import io
import logging
import re

from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaIoBaseDownload

DRIVE_READONLY_SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]


def _build_drive_service(service_account_info: dict):
    """Construct a Drive v3 service client from service-account credentials."""
    credentials = service_account.Credentials.from_service_account_info(
        service_account_info, scopes=DRIVE_READONLY_SCOPES,
    )
    return build('drive', 'v3', credentials=credentials)


def get_file_id_from_share_link(share_link: str) -> str or None:
    """
    Extracts the file ID from a Google Drive share link.

    Args:
        share_link: The Google Drive share link.

    Returns:
        The file ID as a string, or None if the link is invalid.
    """
    try:
        # Split the link by '/'
        parts = share_link.split('/')

        # Find the index of 'd' or 'drive' which usually precedes the file ID
        if 'd' in parts:
            d_index = parts.index('d')
        elif 'drive' in parts:
            d_index = parts.index('drive')
        else:
            raise IndexError

        # The file ID is usually the next part after 'd'
        file_id = parts[d_index + 1]
        subparts = file_id.split('?')
        file_id = subparts[0]

        return file_id
    except ValueError:
        print("Invalid share link format.")
        return None
    except IndexError:
        print("Could not extract file ID from the share link.")
        return None

def extract_folder_id_from_link(folder_link: str) -> str or None:
    """Extract the folder ID from a Google Drive folder share link.

    Supports the common shapes:
      https://drive.google.com/drive/folders/{ID}
      https://drive.google.com/drive/folders/{ID}?usp=sharing
      https://drive.google.com/drive/u/0/folders/{ID}
    """
    if not folder_link:
        return None
    match = re.search(r"/folders/([a-zA-Z0-9_-]+)", folder_link)
    if match:
        return match.group(1)
    return None


def download_file_bytes_sa(service_account_info: dict, file_id: str) -> bytes or None:
    """Download a Drive file by ID and return raw bytes.

    Returns ``None`` on HTTP error so callers can decide whether to skip
    or surface it. Other exceptions propagate.
    """
    try:
        drive_service = _build_drive_service(service_account_info)
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            _, done = downloader.next_chunk()
        return fh.getvalue()
    except HttpError as error:
        status = getattr(getattr(error, 'resp', None), 'status', None)
        if status == 404:
            logging.error(
                f"Drive file '{file_id}' not found (404). "
                "Check the ID and that the file/folder is shared with the service account."
            )
        elif status == 403:
            logging.error(
                f"Permission denied (403) for Drive file '{file_id}'. "
                "Ensure the Drive API is enabled and the folder is shared with the service account."
            )
        else:
            logging.error(f"Drive download failed for '{file_id}': {error}")
        return None


def list_pdfs_in_folder_sa(service_account_info: dict, folder_id: str) -> list[dict]:
    """List PDF files (non-trashed) directly inside a Drive folder.

    Returns a list of dicts with keys ``id``, ``name``, ``modifiedTime``, and
    ``size`` — the fields needed downstream for idempotent ingest.
    """
    drive_service = _build_drive_service(service_account_info)
    files: list[dict] = []
    page_token = None
    query = (
        f"'{folder_id}' in parents and "
        "mimeType='application/pdf' and trashed=false"
    )
    while True:
        response = drive_service.files().list(
            q=query,
            spaces='drive',
            fields='nextPageToken, files(id, name, modifiedTime, size)',
            pageToken=page_token,
            pageSize=100,
        ).execute()
        files.extend(response.get('files', []))
        page_token = response.get('nextPageToken')
        if not page_token:
            break
    return files


def get_notebook_content_from_link_sa(service_account_info: dict, file_id: str):
    """
    Downloads content of a google colab notebook from a given file_id using a service account.

    Args:
        service_account_info: A dictionary of the service account credentials.
        file_id : file_id of the notebook

    Returns:
        The content of the notebook as a string, or None if not found.
    """
    try:
        drive_service = _build_drive_service(service_account_info)

        # Download the file content
        request = drive_service.files().get_media(fileId=file_id)
        fh = io.BytesIO()
        downloader = MediaIoBaseDownload(fh, request)
        done = False
        while not done:
            status, done = downloader.next_chunk()

        # The content is in fh; decode it as UTF-8
        notebook_content = fh.getvalue().decode('utf-8')
        return notebook_content

    except HttpError as error:
        print(f"An HTTP error occurred while accessing Google Drive with Service Account: {error}")
        if error.resp.status == 404:
            print(f"Error 404: File with ID '{file_id}' not found. Check the file ID and that it's shared with the service account.")
        elif error.resp.status == 403:
            print(f"Error 403: Permission denied for file ID '{file_id}'. Ensure the Drive API is enabled and the service account has permissions.")
        return None
    except Exception as e:
        print(f"An unexpected error occurred in get_notebook_content_from_link_sa: {e}")
        return None

def load_notebook_from_google_drive_sa(service_account_info: dict, share_link: str):
    """
    Loads a Colab notebook from Google Drive given its share link, using a service account.

    Args:
        service_account_info: A dictionary containing the service account credentials.
        share_link: The shareable link to the Colab notebook on Google Drive.

    Returns:
        The content of the notebook as a string, or None if it cannot be loaded.
    """
    file_id = get_file_id_from_share_link(share_link)
    if not file_id:
        print("Could not extract file ID from share link.")
        return None
    return get_notebook_content_from_link_sa(service_account_info, file_id)
