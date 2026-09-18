from rest_framework_simplejwt.serializers import TokenObtainPairSerializer


class CyberShieldTokenObtainPairSerializer(TokenObtainPairSerializer):

    def validate(self, attrs):
        data = super().validate(attrs)

        user = self.user

        role = None

        if hasattr(user, 'profile'):
            role = user.profile.role.name

        data['user'] = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'first_name': user.first_name,
            'last_name': user.last_name,
            'role': role,
        }

        return data