from django.contrib import admin
from django.urls import path, include
from .view import health_check
from accounts.views import UserListView

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/health/', health_check, name='health-check'),
    path('api/auth/', include('accounts.urls')),
    # Day 5 MVP: matches frontend api.getUsers() -> GET /api/users/.
    # No new import beyond the view; no router change.
    path('api/users/', UserListView.as_view(), name='user-list'),
    path('api/', include('security.urls')),
]