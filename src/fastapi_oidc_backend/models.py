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
    verify_aud: Optional[bool] = Field(default=None)
    verify_iat: Optional[bool] = Field(default=None)
    verify_exp: Optional[bool] = Field(default=None)
    verify_nbf: Optional[bool] = Field(default=None)
    verify_iss: Optional[bool] = Field(default=None)
    verify_sub: Optional[bool] = Field(default=None)
    verify_jti: Optional[bool] = Field(default=None)
    verify_at_hash: Optional[bool] = Field(default=None)
    require_aud: Optional[bool] = Field(default=True)
    require_iat: Optional[bool] = Field(default=None)
    require_exp: Optional[bool] = Field(default=None)
    require_nbf: Optional[bool] = Field(default=None)
    require_iss: Optional[bool] = Field(default=True)
    require_sub: Optional[bool] = Field(default=None)
    require_jti: Optional[bool] = Field(default=None)
    require_at_hash: Optional[bool] = Field(default=None)
    leeway: Optional[int] = Field(default=None)


class JwtKwargs(BaseModel):
    audience: str
    issuer: str
    algorithms: Optional[Union[str, List[str]]] = Field(default=None)
    subject: Optional[str] = Field(default=None)
    access_token: Optional[str] = Field(default=None)
