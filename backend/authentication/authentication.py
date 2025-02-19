from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.authentication import CSRFCheck
from rest_framework import exceptions
from django.conf import settings

def enforce_csrf(request):
    """
    Enforce CSRF validation for session based authentication.
    """
    check = CSRFCheck()
    check.process_request(request)
    reason = check.process_view(request, None, (), {})
    if reason:
        # CSRF failed, bail with predictable error code
        raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)

class JWTAuthenticationFromCookie(JWTAuthentication):
    def authenticate(self, request):
        refresh_token = request.COOKIES.get(settings.JWT_AUTH_REFRESH_COOKIE)

        if not refresh_token:
            return None

        auth_header = self.get_header(request)
        if auth_header:
            try:
                access_token = self.get_raw_token(auth_header)
                validated_token = self.get_validated_token(access_token)
                user = self.get_user(validated_token)
                return (user, validated_token)
            except Exception:
                pass

        validated_token = self.get_validated_token(refresh_token)
        user = self.get_user(validated_token)

        if not user:
            return None

        # enforce_csrf(request)

        return (user, validated_token)