"""
Authentication and authorization utilities.

Provides OAuth credential helpers, JWT token creation/verification,
and FastAPI dependency functions for user authentication.
"""

import datetime
from typing import Dict, Any

import jwt
from jwt.exceptions import InvalidTokenError
from fastapi import HTTPException, Request

import config


def credentials_to_dict(credentials):
    """Helper function to convert Google credentials to a dictionary."""
    return {'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': credentials.scopes}

def create_jwt_token(user_data: Dict[str, Any], secret_key: str, expires_hours: int = 24) -> str:
    """
    Create a JWT token for authenticated user.

    Args:
        user_data: Dictionary containing user information (id, email, name, etc.)
        secret_key: Secret key for signing the token
        expires_hours: Token expiration time in hours (default 24)

    Returns:
        JWT token as string
    """
    # Set token expiration
    expiration = datetime.datetime.utcnow() + datetime.timedelta(hours=expires_hours)

    # Create JWT payload
    payload = {
        'user_id': user_data.get('id'),
        'email': user_data.get('email'),
        'name': user_data.get('name'),
        'exp': expiration,
        'iat': datetime.datetime.utcnow()
    }

    # Generate token
    token = jwt.encode(payload, secret_key, algorithm='HS256')
    return token

def verify_jwt_token(token: str, secret_key: str) -> Dict[str, Any]:
    """
    Verify and decode a JWT token.

    Args:
        token: JWT token string
        secret_key: Secret key for verification

    Returns:
        Dictionary containing user data from token

    Raises:
        HTTPException: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, secret_key, algorithms=['HS256'])
        return {
            'id': payload.get('user_id'),
            'email': payload.get('email'),
            'name': payload.get('name')
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=401,
            detail="Token has expired. Please login again."
        )
    except InvalidTokenError:
        raise HTTPException(
            status_code=401,
            detail="Invalid authentication token. Please login again."
        )

def get_current_user(request: Request) -> Dict[str, Any]:
    """
    Dependency to get the current authenticated user.
    Supports both JWT token (Authorization header) and session-based authentication.
    Raises 401 if user is not logged in.
    """
    # First check for JWT token in Authorization header
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            user_data = verify_jwt_token(token, config.signing_secret_key)
            return user_data
        except HTTPException:
            # If JWT validation fails, fall through to session check
            pass

    # Fall back to session-based authentication
    if 'user' not in request.session:
        raise HTTPException(
            status_code=401,
            detail="User not authenticated. Please login first at /login or provide a valid Authorization token"
        )
    return request.session['user']

def get_instructor_user(request: Request) -> Dict[str, Any]:
    """
    Dependency to verify the current user is an instructor.
    Add instructor email addresses to the INSTRUCTOR_EMAILS list in the environment.
    """
    user = get_current_user(request)

    user_email = user.get('email', '').lower()

    # Check if user email is in the instructor list
    if user_email not in [email.lower() for email in config.INSTRUCTOR_EMAILS]:
        raise HTTPException(
            status_code=403,
            detail="Access forbidden. This endpoint is only available to instructors."
        )

    return user
