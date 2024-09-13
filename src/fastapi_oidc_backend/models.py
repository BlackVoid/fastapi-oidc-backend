from enum import Enum
from typing import Optional, Union, List

from pydantic import BaseModel, Field


class GrantType(str, Enum):
    AUTHORIZATION_CODE = "authorization_code"
    CLIENT_CREDENTIALS = "client_credentials"
    IMPLICIT = "implicit"
    PASSWORD = "password"


class JwtDecodeOptions(BaseModel):
    verify_signature: Optional[bool] = Field(default=None)
    verify_aud: Optional[bool] = Field(default=True)
    verify_iss: Optional[bool] = Field(default=True)
    verify_iat: Optional[bool] = Field(default=True)
    verify_exp: Optional[bool] = Field(default=True)
    verify_nbf: Optional[bool] = Field(default=True)
    require: List[str] = Field(default_factory=lambda: [])


class JwtKwargs(BaseModel):
    audience: str
    issuer: str
    leeway: int = Field(default=0)
