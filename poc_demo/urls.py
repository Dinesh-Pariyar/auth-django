from django.contrib import admin
from django.urls import path
from api.views import (
    RegisterView,
    LoginView,
    DashboardView,
    ArticleListCreateView,
    ArticleDeatilView,
    TokenRefreshView,
    LogoutView,
)
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
)

urlpatterns = [
    path("admin/", admin.site.urls),
    # path("api/token/", TokenObtainPairView.as_view(), name="token_obtain_pair"),
    path("token/refresh/", TokenRefreshView.as_view(), name="token-refresh"),
    path("api/register/", RegisterView.as_view(), name="register"),
    path("api/login/", LoginView.as_view(), name="login"),
    path("api/logout/", LogoutView.as_view(), name="logout"),
    path("api/dashboard/", DashboardView.as_view(), name="dashboard"),
    path("api/articles/", ArticleListCreateView.as_view(), name="article_list_create"),
    path("api/articles/<int:pk>", ArticleDeatilView.as_view(), name="article_detail"),
]
