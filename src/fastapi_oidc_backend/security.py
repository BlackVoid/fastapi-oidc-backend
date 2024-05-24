from typing import List, Optional

import httpx
from fastapi import Request
from fastapi.exceptions import HTTPException
from fastapi.openapi.models import (
    OAuthFlowAuthorizationCode,
    OAuthFlowClientCredentials,
    OAuthFlowImplicit,
    OAuthFlowPassword,
)
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.openapi.models import OAuth2 as OAuth2Model
from fastapi.security.base import SecurityBase
from fastapi.security.utils import get_authorization_scheme_param
import jwt
from jwt import PyJWTError, PyJWKSet
from starlette.status import HTTP_401_UNAUTHORIZED

from .exceptions import OidcInitException
from .models import GrantType, JwtDecodeOptions, JwtKwargs


class OidcResourceServer(SecurityBase):
    def __init__(
        self,
        oidc_config: JwtKwargs,
        *,
        scheme_name: Optional[str] = "OpenID Connect",
        allowed_grant_types: List[GrantType] = [GrantType.AUTHORIZATION_CODE],
        auto_error: Optional[bool] = True,
        jwt_decode_options: Optional[JwtDecodeOptions] = None,
    ) -> None:
        self.scheme_name = scheme_name
        self.auto_error = auto_error
        self.jwt_decode_options = jwt_decode_options
        self.oidc_config = oidc_config

        self.allowed_grant_types = allowed_grant_types

        self.flows = OAuthFlowsModel()

        self.model = OAuth2Model(flows=self.flows)

        self.well_known: Optional[dict] = None
        self.jwks: PyJWKSet | None = None

    async def load_configuration(self):
        """
        Required to run before it's fully initialized, can be run again to refresh endpoints and keys.
        If fetching fails on start a runtime error will be thrown, otherwse a regular Exception
        :return:
        """
        try:
            async with httpx.AsyncClient() as client:
                self.well_known = await self.fetch_well_known(client)
                self.jwks = PyJWKSet.from_dict(await self.fetch_jwks(client, self.well_known))
        except Exception as e:
            if self.well_known and self.jwks:
                raise OidcInitException("Failed to refresh OIDC configuration") from e
            raise RuntimeError("Failed to initialize OIDC configuration") from e

        grant_types = set(self.well_known["grant_types_supported"])
        grant_types = grant_types.intersection(self.allowed_grant_types)

        authz_url = self.well_known["authorization_endpoint"]
        token_url = self.well_known["token_endpoint"]

        if GrantType.AUTHORIZATION_CODE in grant_types:
            self.flows.authorizationCode = OAuthFlowAuthorizationCode(
                authorizationUrl=authz_url,
                tokenUrl=token_url,
            )

        if GrantType.CLIENT_CREDENTIALS in grant_types:
            self.flows.clientCredentials = OAuthFlowClientCredentials(
                tokenUrl=token_url
            )

        if GrantType.PASSWORD in grant_types:
            self.flows.password = OAuthFlowPassword(tokenUrl=token_url)

        if GrantType.IMPLICIT in grant_types:
            self.flows.implicit = OAuthFlowImplicit(authorizationUrl=authz_url)

        self.model = OAuth2Model(flows=self.flows)

    async def fetch_well_known(self, client: "httpx.AsyncClient") -> dict:
        url = f"{self.oidc_config.issuer}/.well-known/openid-configuration"

        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    async def fetch_jwks(self, client: "httpx.AsyncClient", well_known: dict) -> dict:
        url = well_known["jwks_uri"]

        response = await client.get(url)
        response.raise_for_status()
        return response.json()

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.headers.get("Authorization")
        scheme, param = get_authorization_scheme_param(authorization)

        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            return None

        try:
            key = self.jwks[jwt.get_unverified_header(param).get("kid")].key
            algorithms = self.well_known["token_endpoint_auth_signing_alg_values_supported"]
            return jwt.decode(param, key, algorithms=algorithms, options=self.jwt_decode_options, **self.oidc_config.dict())
        except (PyJWTError, KeyError) as e:
            raise HTTPException(
                status_code=HTTP_401_UNAUTHORIZED,
                detail="JWT validation failed",
                headers={"WWW-Authenticate": "Bearer"},
            ) from e
