import logging
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.exceptions import AuthenticationFailed
from django.http import JsonResponse

logger = logging.getLogger("django")


class TokenRefreshMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        urlpath = str(request.path)
        access_token = request.COOKIES.get("access_token")
        # print(access_token)
        refresh_token = request.COOKIES.get("refresh_token")
        # print(refresh_token)

        if refresh_token:
            try:
                refresh = RefreshToken(refresh_token)
                new_access_token = str(refresh.access_token)
                request.META["HTTP_AUTHORIZATION"] = f"Bearer {new_access_token}"

                response = self.get_response(request)
                response.set_cookie(
                    key="access_token",
                    value=new_access_token,
                    httponly=True,
                    secure=True,
                    samesite="Strict",
                    max_age=refresh.access_token.lifetime.total_seconds(),
                )
                return response
            except Exception as e:
                logger.error(f"Failed to refresh token: {e}")
                return JsonResponse(
                    {"error": "Your session has expired, please login."}, status=401
                )
        if refresh_token is None and not "login" in urlpath:
            return JsonResponse(
                {"error": "Your session has expired, please login."}, status=401
            )

        return self.get_response(request)
