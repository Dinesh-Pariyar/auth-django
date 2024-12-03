from rest_framework.views import exception_handler
from rest_framework.exceptions import PermissionDenied

def custom_exception_handler(exc, context):
    response = exception_handler(exc, context)

    if response is not None:
        if isinstance(exc, PermissionDenied):
            response.data = {
                "error": response.data.get("detail", "Permission denied"),
                "status_code": response.status_code,
            }
    return response
