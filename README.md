# ENAC-IT4R Python Auth Library

A Python library for handling authentication/authorization in the EPFL ENAC IT infrastructure:
 
 * `KeycloakService`: a service to authenticate users with Keycloak and check their roles.
 * `KeycloakAdminService`: a service to manage users and roles in Keycloak for a specific application.

## Usage

To include the authentication library in your project:

```shell
poetry add git+https://github.com/EPFL-ENAC/enacit4r-auth#someref
```

Note: `someref` should be replaced by the commit hash, tag or branch name you want to use.

### KeycloakService
  
```python
from enacit4r_auth.services.auth import KeycloakService, User

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

### KeycloakAdminService

Prerequisites:

1. The client ID and secret are the credentials of a Keycloak client with the "Service accounts roles":
* `realm-management` manage-users
* `realm-management` query-users	
* `realm-management` view-users
* `realm-management` view-realm	

2. The role by which the users will be assigned to the application must be created in Keycloak.

```python
from enacit4r_auth.services.admin import KeycloakAdminService, AppUser


kc_admin_service = KeycloakAdminService(config.KEYCLOAK_URL, config.KEYCLOAK_REALM,
                                        config.KEYCLOAK_API_ID, config.KEYCLOAK_API_SECRET, "my-app-user-role")

```