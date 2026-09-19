from rest_framework.routers import DefaultRouter
from .views import (
    AssetViewSet,
    SecurityFindingViewSet,
    VulnerabilityViewSet,
)

router = DefaultRouter()
router.register(r'assets', AssetViewSet, basename='asset')
router.register(r'findings', SecurityFindingViewSet, basename='finding')
router.register(
    r'vulnerabilities',
    VulnerabilityViewSet,
    basename='vulnerability'
)

urlpatterns = router.urls