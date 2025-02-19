# authentication/apps.py
from django.apps import AppConfig

class AuthenticationConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'authentication'

    def ready(self):
        # Monkey patching code HERE, inside ready()
        from rest_framework_simplejwt.views import TokenRefreshView as SimpleJWTTokenRefreshView
        from rest_framework.response import Response
        import datetime

        def debug_token_refresh_view(original_post):
            def patched_post(self, request, *args, **kwargs):
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                print(f"[{timestamp}] TokenRefreshView (Patched) - post method called")
                print(f"[{timestamp}] TokenRefreshView (Patched) - request.COOKIES: {request.COOKIES}")
                print(f"[{timestamp}] TokenRefreshView (Patched) - request.headers: {request.headers}")
                print(f"[{timestamp}] TokenRefreshView (Patched) - request.data: {request.data}")

                try:
                    response = original_post(self, request, *args, **kwargs)
                    print(f"[{timestamp}] TokenRefreshView (Patched) - Success response: {response.status_code}")
                    return response
                except Exception as e:
                    print(f"[{timestamp}] TokenRefreshView (Patched) - Exception during token refresh: {e}")
                    print(f"[{timestamp}] TokenRefreshView (Patched) - Exception details: {e}")
                    return Response({"error": "Token refresh failed", "details": str(e)}, status=400)

            return patched_post

        original_token_refresh_post = SimpleJWTTokenRefreshView.post
        SimpleJWTTokenRefreshView.post = debug_token_refresh_view(original_token_refresh_post)