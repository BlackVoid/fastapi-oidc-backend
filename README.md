# FastAPI Resource Backend

Build an OIDC resource server using FastAPI.

Your aplication receives the claims decoded from the access token.

Fork of fastapi-resource-server

# Usage

Run keycloak on port 8888:

```sh
docker container run --name auth-server -d -p 8080:8080 \
    -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin \
    quay.io/keycloak/keycloak:latest
```

Install dependencies

```sh
pip install fastapi fastapi_oidc_backend uvicorn
```

Create the main.py module

```python
from fastapi import Depends, FastAPI, Security
from pydantic import BaseModel

from fastapi_oidc_backend.security import OidcResourceServer
from fastapi_oidc_backend.models import JwtKwargs

oidc_config = JwtKwargs(audience="myclient", issuer="http://localhost:8888/realms/myrealm")

app = FastAPI(swagger_ui_init_oauth={"clientId": oidc_config.audience})

auth_scheme = OidcResourceServer(
    oidc_config,
    scheme_name="Keycloak",
)


class User(BaseModel):
    username: str
    given_name: str
    family_name: str
    email: str


def get_current_user(claims: dict = Security(auth_scheme)):
    claims.update(username=claims["preferred_username"])
    user = User.parse_obj(claims)
    return user


@app.get("/users/me")
def read_current_user(current_user: User = Depends(get_current_user)):
    return current_user
```

Run the application

```sh
uvicorn main:app
```
