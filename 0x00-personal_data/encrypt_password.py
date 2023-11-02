#!/usr/bin/env python3

"""
Module for encrypting passwords.
"""

import bcrypt


def hash_password(password: str) -> bytes:
    """
    Hashes a password using bcrypt
    """
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    Validates whether a password matches a hashed password
    """
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password)
