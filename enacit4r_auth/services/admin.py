from typing import List
from keycloak import KeycloakAdmin
from enacit4r_auth.models.auth import AppUser, AppUserDraft


class KeycloakAdminService:
    """A service to interact with keycloak for managing users specific to an application.
    """

    def __init__(self, url: str, realm: str, client_id: str, client_secret: str, app_user_role: str):
        self.kc_admin = KeycloakAdmin(server_url=url,
                                      client_id=client_id,
                                      client_secret_key=client_secret,
                                      realm_name=realm,
                                      verify=True)
        self.app_user_role = app_user_role

    async def get_users(self) -> List[AppUser]:
        """Get the users of the application

        Returns:
            AppUserResult: The users found
        """
        users = self.kc_admin.get_realm_role_members(self.app_user_role)

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

    async def create_user(self, user: AppUserDraft):
        """Create a user with temporary password (required user action: update password)

        Args:
            user (AppUserDraft): The user details

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
            "requiredActions": ["UPDATE_PASSWORD"]
        }
        user_id = self.kc_admin.create_user(payload)
        if user.roles:
            # ensure app user role is always assigned
            if self.app_user_role not in user.roles:
                user.roles.append(self.app_user_role)
        else:
            user.roles = [self.app_user_role]
        roles = [self._get_role(role) for role in user.roles]
        self.kc_admin.assign_realm_roles(user_id, roles)

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
            roles = [self._get_role(role) for role in user.roles]
            self.kc_admin.assign_realm_roles(user.id, roles)
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

    def _get_role(self, name: str):
        """Get role object by name

        Args:
            name (str): The role name

        Returns:
            dict: The Keycloak role object
        """
        return self.kc_admin.get_realm_role(name)

    def _as_app_user(self, user: dict) -> AppUser:
        """Make AppUser object from Keycloak user

        Args:
            user (dict): The Keycloak user

        Returns:
            AppUser: The user
        """
        # Get realm roles for the user
        user_id = user["id"]
        realm_roles = self.kc_admin.get_realm_roles_of_user(user_id)
        realm_role_names = [role["name"] for role in realm_roles]
        return AppUser(
            id=user["id"],
            username=user["username"],
            email=user["email"],
            email_verified=user["emailVerified"],
            totp=user["totp"],
            first_name=user["firstName"],
            last_name=user["lastName"],
            enabled=user["enabled"],
            roles=realm_role_names
        )

