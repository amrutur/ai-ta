"""
Tests for the auth module — JWT creation/verification, credential helpers,
and FastAPI dependency functions for authentication.
"""

import datetime
from unittest.mock import MagicMock

import jwt
import pytest
from fastapi import HTTPException

import config
from auth import (
    create_jwt_token,
    credentials_to_dict,
    get_admin_user,
    get_current_user,
    verify_jwt_token,
)

SECRET = config.signing_secret_key


# ---------------------------------------------------------------------------
# credentials_to_dict
# ---------------------------------------------------------------------------

class TestCredentialsToDict:
    def test_converts_all_fields(self):
        creds = MagicMock()
        creds.token = "access-token"
        creds.refresh_token = "refresh-token"
        creds.token_uri = "https://oauth2.googleapis.com/token"
        creds.client_id = "client-id"
        creds.client_secret = "client-secret"
        creds.scopes = {"openid", "email"}

        result = credentials_to_dict(creds)

        assert result["token"] == "access-token"
        assert result["refresh_token"] == "refresh-token"
        assert result["token_uri"] == "https://oauth2.googleapis.com/token"
        assert result["client_id"] == "client-id"
        assert result["client_secret"] == "client-secret"
        assert set(result["scopes"]) == {"openid", "email"}

    def test_none_scopes_returns_empty_list(self):
        creds = MagicMock()
        creds.scopes = None
        result = credentials_to_dict(creds)
        assert result["scopes"] == []


# ---------------------------------------------------------------------------
# create_jwt_token / verify_jwt_token round-trip
# ---------------------------------------------------------------------------

class TestJWT:
    def _user_data(self):
        return {"id": "u123", "email": "alice@example.com", "name": "Alice"}

    def test_create_returns_string(self):
        token = create_jwt_token(self._user_data(), SECRET)
        assert isinstance(token, str)

    def test_roundtrip(self):
        token = create_jwt_token(self._user_data(), SECRET)
        result = verify_jwt_token(token, SECRET)
        assert result["id"] == "u123"
        assert result["email"] == "alice@example.com"
        assert result["name"] == "Alice"

    def test_custom_expiration(self):
        token = create_jwt_token(self._user_data(), SECRET, expires_hours=1)
        payload = jwt.decode(token, SECRET, algorithms=["HS256"])
        iat = payload["iat"]
        exp = payload["exp"]
        # Should expire ~1 hour after issued
        assert 3500 <= (exp - iat) <= 3700

    def test_expired_token_raises_401(self):
        token = create_jwt_token(self._user_data(), SECRET, expires_hours=-1)
        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_token(token, SECRET)
        assert exc_info.value.status_code == 401
        assert "expired" in exc_info.value.detail.lower()

    def test_invalid_token_raises_401(self):
        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_token("not-a-valid-token", SECRET)
        assert exc_info.value.status_code == 401
        assert "invalid" in exc_info.value.detail.lower()

    def test_wrong_secret_raises_401(self):
        token = create_jwt_token(self._user_data(), SECRET)
        with pytest.raises(HTTPException) as exc_info:
            verify_jwt_token(token, "wrong-secret-key-that-is-long-enough")
        assert exc_info.value.status_code == 401

    def test_missing_fields_return_none(self):
        token = create_jwt_token({}, SECRET)
        result = verify_jwt_token(token, SECRET)
        assert result["id"] is None
        assert result["email"] is None
        assert result["name"] is None


# ---------------------------------------------------------------------------
# get_current_user
# ---------------------------------------------------------------------------

class TestGetCurrentUser:
    def _make_request(self, auth_header=None, session_user=None):
        headers = {}
        if auth_header:
            headers["Authorization"] = auth_header
        session = {}
        if session_user:
            session["user"] = session_user

        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default=None: headers.get(key, default)
        req.session = session
        return req

    def test_jwt_auth(self):
        token = create_jwt_token({"id": "u1", "email": "a@b.com", "name": "A"}, SECRET)
        req = self._make_request(auth_header=f"Bearer {token}")
        user = get_current_user(req)
        assert user["email"] == "a@b.com"

    def test_session_fallback(self):
        session_user = {"id": "u2", "email": "b@c.com", "name": "B"}
        req = self._make_request(session_user=session_user)
        user = get_current_user(req)
        assert user == session_user

    def test_no_auth_raises_401(self):
        req = self._make_request()
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(req)
        assert exc_info.value.status_code == 401

    def test_invalid_jwt_falls_through_to_session(self):
        session_user = {"id": "u3", "email": "c@d.com", "name": "C"}
        req = self._make_request(auth_header="Bearer bad-token", session_user=session_user)
        user = get_current_user(req)
        assert user == session_user

    def test_invalid_jwt_no_session_raises_401(self):
        req = self._make_request(auth_header="Bearer bad-token")
        with pytest.raises(HTTPException) as exc_info:
            get_current_user(req)
        assert exc_info.value.status_code == 401


# ---------------------------------------------------------------------------
# get_admin_user
# ---------------------------------------------------------------------------

class TestGetAdminUser:
    def _make_request(self, email):
        token = create_jwt_token({"id": "u1", "email": email, "name": "Test"}, SECRET)
        headers = {"Authorization": f"Bearer {token}"}
        req = MagicMock()
        req.headers = MagicMock()
        req.headers.get = lambda key, default=None: headers.get(key, default)
        req.session = {}
        return req

    def test_admin_allowed(self):
        req = self._make_request(config.admin_email)
        user = get_admin_user(req)
        assert user["email"] == config.admin_email

    def test_non_admin_rejected(self):
        req = self._make_request("not-admin@test.com")
        with pytest.raises(HTTPException) as exc_info:
            get_admin_user(req)
        assert exc_info.value.status_code == 403

    def test_admin_email_case_insensitive(self):
        req = self._make_request(config.admin_email.upper())
        # The function lowercases the email before comparing
        user = get_admin_user(req)
        assert user["email"].lower() == config.admin_email.lower()
