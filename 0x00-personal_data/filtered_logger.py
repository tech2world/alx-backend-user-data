#!/usr/bin/env python3

"""
Module for logging and connecting to a secure database.
"""

import os
import mysql.connector
import logging
import re
from typing import List


PII_FIELDS: List[str] = ["name", "email", "phone", "ssn", "password"]


class RedactingFormatter(logging.Formatter):
    """
    Redacting Formatter class
    """

    def __init__(self, fields: List[str]):
        super().__init__("[HOLBERTON] user_data %(levelname)s \
                         %(asctime)-15s: %(message)s")
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """
        Format the record
        """
        log_message = super().format(record)
        for field in self.fields:
            log_message = filter_datum([field], "***", log_message, ";")
        return log_message


def filter_datum(fields: List[str], redaction: str, message: str,
                 separator: str) -> str:
    """
    Returns the log message obfuscated
    """
    pattern = r'(' + '|'.join(fields) + r')=.*?' + separator
    return re.sub(pattern, lambda x: x.group(1) + '=' + redaction +
                  separator, message)


def get_logger() -> logging.Logger:
    """
    Returns a Logger object named "user_data"
    """
    logger = logging.getLogger('user_data')
    logger.setLevel(logging.INFO)
    logger.propagate = False
    stream_handler = logging.StreamHandler()
    formatter = RedactingFormatter(PII_FIELDS)
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """
    Returns a connector to the database
    (mysql.connector.connection.MySQLConnection object)
    """
    username = os.getenv('PERSONAL_DATA_DB_USERNAME', 'root')
    password = os.getenv('PERSONAL_DATA_DB_PASSWORD', '')
    host = os.getenv('PERSONAL_DATA_DB_HOST', 'localhost')
    database = os.getenv('PERSONAL_DATA_DB_NAME')

    return mysql.connector.connect(
        user=username,
        password=password,
        host=host,
        database=database
    )


def main() -> None:
    """
    Retrieve all rows in the users table and display each row under
    a filtered format
    """
    logger = get_logger()
    db = get_db()
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users;")
    for row in cursor:
        formatted_row = '; '.join(f'{k}={v}' for k, v in zip(PII_FIELDS, row))
        logger.info(formatted_row)
    cursor.close()
    db.close()


if __name__ == "__main__":
    main()
