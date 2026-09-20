from rest_framework.routers import DefaultRouter
from .views import (
    AssetViewSet,
    AuditLogViewSet,
    NotificationViewSet,
    RemediationViewSet,
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
# Day 6: real endpoints matching the existing frontend api paths
# ('remediation/', 'notifications/', 'audit-logs/').
router.register(r'remediation', RemediationViewSet, basename='remediation')
router.register(r'notifications', NotificationViewSet, basename='notification')
router.register(r'audit-logs', AuditLogViewSet, basename='auditlog')

urlpatterns = router.urls