from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Role, UserRole, Article


class UserSerializer(serializers.ModelSerializer):
    roles = serializers.SerializerMethodField()

    class Meta:
        model = User
        fields = ("id", "username", "email", "roles")

    def get_roles(self, obj):
        return [role.role.name for role in obj.user_roles.all()]


class RegisterSerializer(serializers.ModelSerializer):
    role = serializers.CharField(required=False)

    class Meta:
        model = User
        fields = ("username", "email", "password", "role")
        extra_kwargs = {
            "password": {"write_only": True},
        }

    def create(self, validated_data):
        role_name = validated_data.pop("role", None)

        # Get the currently logged in user
        created_by_user = self.context["request"].user

        # Create the User
        user = User.objects.create_user(
            username=validated_data["username"],
            email=validated_data["email"],
            password=validated_data["password"],
        )

        # Assign role based on the creator's role
        if created_by_user.is_superuser:
            role_name = "MASTER"
        else:
            creator_role = created_by_user.user_roles.first().role.name
            if creator_role == "MASTER":
                role_name = "User"

        if role_name:
            role, created = Role.objects.get_or_create(name=role_name)
            UserRole.objects.create(user=user, role=role)

        return user

    def to_representation(self, instance):
        return {
            "id": instance.id,
            "username": instance.username,
            "email": instance.email,
            "roles": [role.role.name for role in instance.user_roles.all()],
        }


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True)
    password = serializers.CharField(required=True, write_only=True)


class ArticleSerializer(serializers.ModelSerializer):
    author = UserSerializer(read_only=True)

    class Meta:
        model = Article
        fields = ("id", "title", "content", "author", "created_at", "updated_at")
