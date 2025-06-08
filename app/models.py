from sqlmodel import SQLModel, Field

from typing import Optional

from pydantic import EmailStr

from passlib.context import CryptContext

from datetime import datetime
from datetime import date as date_type

import re

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class PasswordError(Exception):
    """Exception raised for errors in password validation."""
    def __init__(self, message: str = "Invalid password"):
        super().__init__(message)
        self.message = message

class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str
    email: EmailStr
    password: str

    def set_password(self, raw_password: str):
        """
        sets a password for the user after validating against a specific pattern for
        security. The password must match the defined security requirements for
        complexity. Once validated, it hashes the password using a secure hashing
        algorithm and stores it.

        :param raw_password: The plain text password to be set. The password must
            meet the following criteria: at least one lowercase letter, one uppercase
            letter, one numeral, one special character, and a minimum length of 8 characters.
        :type raw_password: Str
        :return: None
        :raises ValueError: If the provided raw_password does not meet the required
            pattern for password complexity.
        """
        pattern = r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$'
        if re.match(pattern, raw_password) is None:
            raise PasswordError(message=f"value: {raw_password} does not match the required pattern")

        self.password = pwd_context.hash(raw_password)

    def check_password(self, raw_password: str) -> bool:
        """Verifica la contraseña en texto plano contra el hash almacenado."""
        return pwd_context.verify(raw_password, self.password)