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