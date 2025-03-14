from typing import Annotated

from pydantic import BaseModel, EmailStr, field_validator, Field

from database import accounts_validators
from database.validators.accounts import validate_password_strength


class UserRegistrationRequestSchema(BaseModel):
    email: EmailStr
    password: str

    @field_validator("password")
    @classmethod
    def validate_password(cls, value: str) -> str:
        return validate_password_strength(value)

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "user@example.com",
                "password": "SecurePassword123!"
            }
        }
    }


class UserRegistrationResponseSchema(BaseModel):
    id: int
    email: EmailStr

    model_config = {
        "json_schema_extra": {
            "example": {
                "id": 1,
                "email": "user@example.com"
            }
        }
    }


class UserActivationRequestSchema(BaseModel):
    email: EmailStr
    token: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "email": "test@example.com",
                "token": "activation_token"
            }
        }
    }


class MessageResponseSchema(BaseModel):
    message: str

    model_config = {
        "json_schema_extra": {
            "example": {
                "message": "User account activated successfully."
            }
        }
    }
