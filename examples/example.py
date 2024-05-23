from contextlib import asynccontextmanager
from typing import Set, Optional, List

from fastapi import Depends, FastAPI, Security, HTTPException
from pydantic import BaseModel
from starlette.status import HTTP_403_FORBIDDEN

from fastapi_oidc_backend.models import JwtKwargs
from fastapi_oidc_backend.security import OidcResourceServer


@asynccontextmanager
async def app_startup(_app: FastAPI):
    await auth_scheme.load_configuration()
    yield

oidc_config = JwtKwargs(issuer="http://localhost:8080/realms/myrealm", audience="myclient")

app = FastAPI(lifespan=app_startup,
              swagger_ui_init_oauth={
                  "clientId": oidc_config.audience,
                  "usePkceWithAuthorizationCodeGrant": True
              })

auth_scheme = OidcResourceServer(
    oidc_config,
    scheme_name="Keycloak"
)

class User(BaseModel):
    username: str
    given_name: str
    family_name: str
    email: str
    roles: Set[str]


class CurrentUser:
    def __init__(self, required_roles: Optional[List[Set[str]]] = None):
        self.required_roles = required_roles or []

    def __call__(self, claims: dict = Security(auth_scheme)):
        claims.update(username=claims["preferred_username"])
        claims.update(roles=claims.get("resource_access", {}).get(oidc_config.audience, {}).get("roles", []))
        user = User.parse_obj(claims)

        if self.required_roles:
            for roles in self.required_roles:
                if len(user.roles.intersection(roles)) == len(roles):
                    return user
            raise HTTPException(
                status_code=HTTP_403_FORBIDDEN,
                detail="Not authorized to access this resource",
            )
        return user


@app.get("/users/me")
def read_current_user(current_user: User = Depends(CurrentUser())):
    return current_user


@app.get("/users")
def read_current_user(current_user: User = Depends(CurrentUser(required_roles=[{"admin"},]))):
    return [current_user]
