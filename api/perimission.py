from rest_framework.permissions import BasePermission


class IsAdminOrMaster(BasePermission):
    def has_permission(self, request, view):

        if request.user.is_superuser:
            return True

        user_role = request.user.user_roles.first().role.name
        return user_role in ["ADMIN", "MASTER"]


class IsUserRole(BasePermission):
    def has_permission(self, request, view):

        user_role = request.user.user_roles.first().role.name
        return user_role in [
            "USER",
        ]


class IsMasterOrUserRole(BasePermission):
    def has_permission(self, request, view):

        user_role = request.user.user_roles.first().role.name
        return user_role in [
            "MASTER","USER"
        ]


class IsAdminRole(BasePermission):
    def has_permission(self, request, view):

        user_role = request.user.user_roles.first().role.name
        return user_role in [
            "ADMIN",
        ]
