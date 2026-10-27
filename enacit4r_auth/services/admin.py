from functools import cached_property
from typing import List
from keycloak import KeycloakAdmin
from enacit4r_auth.models.auth import AppUser, AppUserDraft


class KeycloakAdminService:
    """A service to interact with keycloak for managing users specific to an application.
    """

    def __init__(self, url: str, realm: str, client_id: str, client_secret: str, app_user_role: str, client_roles: bool = False):
        """client_roles: manage the roles of this client instead of the realm roles
        (requires the realm-management view-clients role)."""
        self.kc_admin = KeycloakAdmin(server_url=url,
                                      client_id=client_id,
                                      client_secret_key=client_secret,
                                      realm_name=realm,
                                      verify=True)
        self.app_user_role = app_user_role
        self.client_id = client_id
        self.client_roles = client_roles

    async def get_users(self) -> List[AppUser]:
        """Get the users of the application

        Returns:
            AppUserResult: The users found
        """
        return await self.get_users_for_role(self.app_user_role)

    async def get_users_for_role(self, role: str) -> List[AppUser]:
        """Get the users of the application for a specific role

        Args:
            role (str): The role to filter users by
        
        Returns:
            AppUserResult: The users found
        """
        users = self._get_role_members(role)

        # Fetch Roles for Each User
        app_users = []
        for user in users:
            app_user = self._as_app_user(user)
            app_users.append(app_user)

        return app_users

    async def get_user(self, id_or_name: str) -> AppUser:
        """Get a user by id or name

        Args:
            id_or_name (str): The user id or name

        Returns:
            AppUser: The user
        """
        user_id = id_or_name
        try:
            user_id = self.kc_admin.get_user_id(id_or_name)
        except:
            pass
        if user_id is None:
            user_id = id_or_name
        user = self.kc_admin.get_user(user_id)
        return self._as_app_user(user)

    async def create_user(self, user: AppUserDraft, actions: List[str] = ["UPDATE_PASSWORD"]) -> AppUser:
        """Create a user with temporary password (required user action: update password)

        Args:
            user (AppUserDraft): The user details
            actions (List[str], optional): The required actions for the user: UPDATE_PASSWORD, 
            CONFIGURE_TOTP, VERIFY_EMAIL, UPDATE_PROFILE etc. Defaults to ["UPDATE_PASSWORD"].

        Returns:
            AppUser: The user created
        """
        payload = {
            "username": user.username,
            "email": user.email,
            "emailVerified": user.email_verified,
            "firstName": user.first_name,
            "lastName": user.last_name,
            "enabled": user.enabled,
            "credentials": [{"value": user.password, "type": "password"}],
            "requiredActions": actions or ["UPDATE_PASSWORD"],
        }
        user_id = self.kc_admin.create_user(payload)
        if user.roles:
            # ensure app user role is always assigned
            if self.app_user_role not in user.roles:
                user.roles.append(self.app_user_role)
        else:
            user.roles = [self.app_user_role]
        roles = [self._get_role(role) for role in user.roles]
        self._assign_roles(user_id, roles)

        return await self.get_user(user_id)

    async def update_user(self, user: AppUser):
        """Update user details: email, first_name, last_name, enabled, roles

        Args:
            user (AppUser): The user details

        Returns:
            AppUser: The user updated
        """
        payload = {}
        if user.email:
            payload["email"] = user.email
        if user.first_name:
            payload["firstName"] = user.first_name
        if user.last_name:
            payload["lastName"] = user.last_name
        if user.enabled is not None:
            payload["enabled"] = user.enabled
        self.kc_admin.update_user(user.id, payload)

        if user.roles:
            # ensure app user role is always assigned
            if self.app_user_role not in user.roles:
                user.roles.append(self.app_user_role)
            current_roles = self._get_roles_of_user(user.id)
            # delete roles that are not in the new list
            roles_to_delete = [role for role in current_roles if role["name"] not in user.roles]
            if len(roles_to_delete) > 0:
                self._delete_roles(user.id, roles_to_delete)
            # assign roles that are in the new list
            current_role_names = [role["name"] for role in current_roles]
            roles_to_add = [self._get_role(role) for role in user.roles if role not in current_role_names]
            if len(roles_to_add) > 0:
                self._assign_roles(user.id, roles_to_add)
        return await self.get_user(user.id)

    async def update_user_password(self, id: str, password: str) -> None:
        """Set temporary password for user

        Args:
            id (str): The user id
            password (str): The password
        """
        # ensure valid user
        await self.get_user(id)
        self.kc_admin.set_user_password(id, password, temporary=True)

    async def delete_user(self, id: str):
        """Delete user

        Args:
            id (str): The user id or name

        Returns:
            AppUser: The deleted user
        """
        try:
            user = await self.get_user(id)
            self.kc_admin.delete_user(user.id)
        except:
            self.kc_admin.delete_user(id)
        return user
    
    def check_valid_password(self, password: str, min_length: int = 8) -> bool:
        """Check a user password is valid: at least <min_length> characters, lower and upper case letters, at least one digit and a special char.

        Args:
            password (str): The password to check
            min_length (int): The minimum length of the password. Defaults to 8.

        Returns:
            bool: True if the password is valid, False otherwise
        """
        if len(password) < min_length:
            return False
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        return has_lower and has_upper and has_digit and has_special
        

    def _get_role(self, name: str):
        """Get role object by name

        Args:
            name (str): The role name

        Returns:
            dict: The Keycloak role object
        """
        if self.client_roles:
            return self.kc_admin.get_client_role(self._client_uuid, name)
        return self.kc_admin.get_realm_role(name)

    @cached_property
    def _client_uuid(self) -> str:
        """Internal id of the client that holds the application roles"""
        return self.kc_admin.get_client_id(self.client_id)

    def _get_role_members(self, role: str) -> List[dict]:
        if self.client_roles:
            return self.kc_admin.get_client_role_members(self._client_uuid, role)
        return self.kc_admin.get_realm_role_members(role)

    def _get_roles_of_user(self, user_id: str) -> List[dict]:
        if self.client_roles:
            return self.kc_admin.get_client_roles_of_user(user_id, self._client_uuid)
        return self.kc_admin.get_realm_roles_of_user(user_id)

    def _assign_roles(self, user_id: str, roles: List[dict]):
        if self.client_roles:
            self.kc_admin.assign_client_role(user_id, self._client_uuid, roles)
        else:
            self.kc_admin.assign_realm_roles(user_id, roles)

    def _delete_roles(self, user_id: str, roles: List[dict]):
        if self.client_roles:
            self.kc_admin.delete_client_roles_of_user(user_id, self._client_uuid, roles)
        else:
            self.kc_admin.delete_realm_roles_of_user(user_id, roles)

    def _as_app_user(self, user: dict) -> AppUser:
        """Make AppUser object from Keycloak user

        Args:
            user (dict): The Keycloak user

        Returns:
            AppUser: The user
        """
        # Get application roles for the user
        user_id = user["id"]
        role_names = [role["name"] for role in self._get_roles_of_user(user_id)]
        return AppUser(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            email_verified=user["emailVerified"],
            totp=user["totp"],
            first_name=user["firstName"],
            last_name=user["lastName"],
            enabled=user["enabled"],
            roles=role_names
        )
