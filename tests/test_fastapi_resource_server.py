from fastapi_oidc_backend.models import GrantType


def test_grant_type():
    assert GrantType.AUTHORIZATION_CODE.value == "authorization_code"
