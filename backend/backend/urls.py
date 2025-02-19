# backend/urls.py
from django.contrib import admin
from django.urls import path, include

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/auth/', include('authentication.urls')), # <--- Include authentication URLs
    path('api/file/', include('files.urls')),
]