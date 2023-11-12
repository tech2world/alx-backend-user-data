#!/usr/bin/env python3
"""
Basic Authentication module
"""

import base64
from typing import TypeVar
from api.v1.auth.auth import Auth

from models.user import User


class BasicAuth(Auth):
    """
    BasicAuth that inherits from Auth
    """

    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """
        Returns the Base64 part of the Authorization header for Basic Auth.
        Returns None if authorization_header is None, not a string,
        or doesn't start with 'Basic '.
        """
        if authorization_header is None:
            return None

        if not isinstance(authorization_header, str):
            return None

        if not authorization_header.startswith('Basic '):
            return None

        # Split the authorization_header at the first space
        return authorization_header.split(" ", 1)[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Returns the decoded value of Base64 string base64_authorization_header
        Returns None if base64_authorization_header is None or not a string.
        Returns None if base64_authorization_header is not a valid Base64.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            # Use base64.urlsafe_b64decode instead of base64.b64decode
            decoded_bytes = base64.urlsafe_b64decode(
                            base64_authorization_header)
            # Decode the bytes using UTF-8, ignore errors
            return decoded_bytes.decode('utf-8', errors='ignore')

        except (base64.binascii.Error, UnicodeDecodeError):
            return None

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """
        Returns the decoded value of Base64 string base64_authorization_header
        Returns None if base64_authorization_header is None or not a string.
        Returns None if base64_authorization_header is not a valid Base64.
        """
        if base64_authorization_header is None:
            return None

        if not isinstance(base64_authorization_header, str):
            return None

        try:
            to_decode = base64_authorization_header.encode('utf-8')
            decoded = base64.b64decode(to_decode)
            return decoded.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self, decoded_base64_authorization_header:
                                 str) -> (str, str):
        """
        Returns the user email and password from the Base64 decoded value.
        Returns (None, None) if decoded_base64_authorization_header is None
        or not a string.
        Returns (None, None) if decoded_base64_authorization_header does not
        contain ':'.
        else, returns the user email and the user password separated by ':'.
        """
        if decoded_base64_authorization_header is None:
            return (None, None)

        if not isinstance(decoded_base64_authorization_header, str):
            return (None, None)

        if ':' not in decoded_base64_authorization_header:
            return (None, None)

        email, password = decoded_base64_authorization_header.split(':', 1)
        return (email, password)

    def user_object_from_credentials(self, user_email: str, user_pwd: str
                                     ) -> TypeVar('User'):
        """
        Returns the User instance based on email and password.
        Returns None if user_email or user_pwd is None or not a string.
        Returns None if the database does not contain any User instance
        with email equal to user_email.

        Returns None if user_pwd is not the passwrd of the User instance found
        Otherwise, returns the User instance.
        """
        if user_email is None or not isinstance(user_email, str):
            return None

        if user_pwd is None or not isinstance(user_pwd, str):
            return None

        users = User.search({'email': user_email})

        if not users or users == []:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Overloads Auth and retrieves the User instance for a request.
        """
        if request is None:
            return None

        authorization_header = self.authorization_header(request)
        if authorization_header is None:
            return None

        base64_auth_header = self.extract_base64_authorization_header(
            authorization_header)

        if base64_auth_header is None:
            return None

        decoded_auth_header = self.decode_base64_authorization_header(
            base64_auth_header)

        if decoded_auth_header is None:
            return None

        user_email, user_pwd = self.extract_user_credentials(
                                            decoded_auth_header)

        if user_email is None or user_pwd is None:
            return None

        return self.user_object_from_credentials(user_email, user_pwd)
