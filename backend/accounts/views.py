from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from .serializers import CyberShieldTokenObtainPairSerializer
from .permissions import IsAdministrator


class CyberShieldTokenObtainPairView(TokenObtainPairView):
    serializer_class = CyberShieldTokenObtainPairSerializer


class CurrentUserView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        user = request.user

        role = None
        if hasattr(user, 'profile'):
            role = user.profile.role.name

        return Response({
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': role,
        })

class AdminOnlyView(APIView):
    permission_classes = [IsAdministrator]

    def get(self, request):
        return Response({
            'message': 'You have Administrator access.'
        })


class UserListView(APIView):
    """Safe user list for the vulnerability-assignment dropdown (Day 5 MVP).

    Returns id/username/email/first/last/role/is_active only — never passwords.
    Requires authentication; any authenticated role may read (writes are
    still restricted by the analyst-only actions in security/views.py).
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from django.contrib.auth.models import User

        users = (
            User.objects.select_related('profile__role')
            .order_by('username')
        )
        data = []
        for u in users:
            role = None
            try:
                role = u.profile.role.name
            except Exception:
                role = None
            data.append({
                'id': u.id,
                'username': u.username,
                'email': u.email,
                'first_name': u.first_name,
                'last_name': u.last_name,
                'role': role,
                'is_active': u.is_active,
            })
        return Response(data)