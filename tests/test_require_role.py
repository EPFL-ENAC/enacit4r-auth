import pytest
from enacit4r_auth.services.auth import KeycloakService
from enacit4r_auth.models.auth import User

@pytest.mark.asyncio
async def test_require_admin():
    kc_service = _make_kc_service()
    require_admin_impl = kc_service.require_admin()
    
    user = _make_user(["admin"])
    assert user == await require_admin_impl(user)
    
    user = _make_user(["editor"])
    try:
        await require_admin_impl(user)
        assert False
    except Exception as e:
        assert True    

@pytest.mark.asyncio
async def test_require_role():
    kc_service = _make_kc_service()
    require_role_impl = kc_service.require_role("editor")
    
    user = _make_user(["editor"])
    assert user == await require_role_impl(user)
    
    user = _make_user(["a_role"])
    try:
        await require_role_impl(user)
        assert False
    except Exception as e:
        assert True

@pytest.mark.asyncio
async def test_require_any_role():
    kc_service = _make_kc_service()
    require_any_role_impl = kc_service.require_any_role(["admin", "editor"])
    
    user = _make_user(["editor"])
    assert user == await require_any_role_impl(user)
    user = _make_user(["admin"])
    assert user == await require_any_role_impl(user)
    user = _make_user(["admin", "a_role"])
    assert user == await require_any_role_impl(user)
    
    user = _make_user(["a_role"])
    try:
        await require_any_role_impl(user)
        assert False
    except Exception as e:
        assert True

def _make_kc_service():
    return KeycloakService(
        url="https://enac-it-sso.epfl.ch",
        realm="SOMEAPP",
        client_id="test-api",
        client_secret="xxxx-xxxx-xxxx-xxxx",
        admin_role="admin",
    )
 
def _make_user(roles: list[str]):
    return User(id="abc", username="test", email="test@me.com", first_name="Foo", last_name="Bar", client_roles=roles, realm_roles=roles)