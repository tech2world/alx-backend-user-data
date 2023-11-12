#!usr/bin/env pyhon3
""" Template for authentication
"""

from flask import request
from typing import List, TypeVar


class Auth():
    """
    Authentication class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
         Check if authentication is required for the given path.

        Returns True if path is None, excluded_paths is None,
        or excluded_paths is empty.

        Returns False if path is in excluded_paths.

        Args:
            path (str): The path to check for authentication.
            excluded_paths (List[str]): List of paths excluded
            from authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True
        for excluded_path in excluded_paths:
            if path.startswith(excluded_path):
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """
        Retrieve the authorization header from the request.

        Args:
            request: The request object.

        Returns:
            str: The value of the Authorization header.
        """
        if request is None:
            return None
        if 'Authorization' not in request.headers:
            return None
        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """
        Retrieve the current user based on the request.

        Args:
            request: The request object.

        Returns:
            TypeVar('User'): The current user.
        """
        return None

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        Determines if the path requires authentication.

        path: The path to check.
        excluded_paths: A list of paths that are excluded from authentication.
        return: True if authentication is required, False otherwise.
        """
        if not path or not isinstance(path, str):
            return True

        for excluded_path in excluded_paths:
            if excluded_path.endswith('*') and path.startswith(
                                                excluded_path[:-1]):
                return False
            elif path == excluded_path:
                return False

        return True
