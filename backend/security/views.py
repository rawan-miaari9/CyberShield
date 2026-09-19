from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated

from .models import Asset, SecurityFinding, Vulnerability
from .serializers import (
    AssetSerializer,
    SecurityFindingSerializer,
    VulnerabilitySerializer,
)


class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all().order_by('-created_at')
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]


class SecurityFindingViewSet(viewsets.ModelViewSet):
    queryset = SecurityFinding.objects.all().order_by('-imported_at')
    serializer_class = SecurityFindingSerializer
    permission_classes = [IsAuthenticated]


class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all().order_by('-created_at')
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]