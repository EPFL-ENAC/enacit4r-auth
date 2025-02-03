from pydantic import BaseModel
from typing import Optional, List

# User as it lives in the Keycloak database

class User(BaseModel):
    id: str
    username: str
    email: str
    first_name: str
    last_name: str
    realm_roles: list
    client_roles: list


# User of the application as it is returned by the Keycloak API
class AppUser(BaseModel):
    id: Optional[str] = None
    username: str
    email: str
    email_verified: bool
    first_name: Optional[str]
    last_name: Optional[str]
    enabled: bool
    totp: Optional[bool] = False
    roles: List[str]


class AppUserDraft(AppUser):
    password: str


class AppUserPassword(BaseModel):
    password: str
