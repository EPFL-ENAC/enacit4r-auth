# ENAC-IT4R Python Auth Library

A Python library for handling authentication/authorization in the EPFL ENAC IT infrastructure:
 
 * `KeycloakService`: a service to authenticate users with Keycloak and check their roles.

## Usage

To include the authentication library in your project:

```shell
poetry add git+https://github.com/EPFL-ENAC/enacit4r-auth#someref
```

Note: `someref` should be replaced by the commit hash, tag or branch name you want to use.

### KeycloakService
  
```python
from enacit4r_auth.services.keycloak import KeycloakService, User

# Users from a Keycloak realm are assigned application specific roles
kc_service = KeycloakService(config.KEYCLOAK_URL, config.KEYCLOAK_REALM, 
    config.KEYCLOAK_CLIENT_ID, config.KEYCLOAK_CLIENT_SECRET, "myapp-admin-role")


# Example usage with FastAPI
@router.delete("/entity/{id}",
               description="Delete an entity, requires administrator role",)
async def delete_entity(id: str, user: User = Depends(kc_service.require_admin())):
    pass

@router.put("/entity/{id}",
            description="Update an entity, requires admin or editor role",)
async def update_entity(id: str, user: User = Depends(kc_service.require_any_role(["myapp-admin-role", "myapp-editor-role"]))):
    pass


```
