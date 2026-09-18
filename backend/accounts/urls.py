from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from .views import CyberShieldTokenObtainPairView, CurrentUserView, AdminOnlyView

urlpatterns = [
    path('login/', CyberShieldTokenObtainPairView.as_view(), name='login'),
    path('refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('me/', CurrentUserView.as_view(), name='current_user'),
    path('admin-only/', AdminOnlyView.as_view(), name='admin_only'),
]