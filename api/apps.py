from django.apps import AppConfig
from django.db.models.signals import post_migrate


class ApiConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "api"

    def ready(self):
        from django.contrib.auth import get_user_model
        from .models import Role, UserRole

        post_migrate.connect(create_initial_user_and_roles, sender=self)


def create_initial_user_and_roles(sender, **kwargs):
    from django.contrib.auth import get_user_model
    from .models import Role, UserRole

    admin_role, __ = Role.objects.get_or_create(name="ADMIN")
    master__role, __ = Role.objects.get_or_create(name="MASTER")
    user_role, __ = Role.objects.get_or_create(name="USER")

    User = get_user_model()

    if not User.objects.filter(username="admin").exists():
        admin_user = User.objects.create_superuser(
            username="admin",
            email="admin@admin.com",
            password="admin",
        )

        UserRole.objects.create(user=admin_user, role=admin_role)
