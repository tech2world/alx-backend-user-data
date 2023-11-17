#!/usr.bin/env python3
"""auth module
"""
from db import DB
from user import User
from typing import TypeVar
import bcrypt

class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def _hash_password(self, password: str) -> bytes:
        """Hash a password using bcrypt
        """
        # Generate a salt and hash the password
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)

        return hashed_password

    def register_user(self, email: str, password: str) -> TypeVar('User'):
        """Register a new user
        """
        # Check if user with the provided email already exists
        try:
            self._db.find_user_by(email=email)
            raise ValueError("User {} already exists".format(email))
        except:
            # If NoResultFound exception is raised, user does not exist
            pass

        # Hash the password
        hashed_password = self._hash_password(password)

        # Create a new user
        new_user = self._db.add_user(email, hashed_password)

        return new_user
