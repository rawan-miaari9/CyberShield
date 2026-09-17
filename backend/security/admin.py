from django.contrib import admin
from .models import (
    Asset,
    ScannerIntegration,
    SecurityFinding,
    Vulnerability,
    RemediationTask,
    AIAnalysis,
    Notification,
    AuditLog,
)


@admin.register(Asset)
class AssetAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'asset_type', 'criticality', 'is_active')
    search_fields = ('name', 'hostname', 'ip_address', 'url')
    list_filter = ('asset_type', 'criticality', 'is_active')


@admin.register(ScannerIntegration)
class ScannerIntegrationAdmin(admin.ModelAdmin):
    list_display = ('id', 'name', 'scanner_type', 'status', 'is_enabled', 'last_sync_at')
    list_filter = ('scanner_type', 'status', 'is_enabled')


@admin.register(SecurityFinding)
class SecurityFindingAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'asset', 'severity', 'status', 'imported_at')
    search_fields = ('title', 'fingerprint', 'external_id')
    list_filter = ('severity', 'status', 'integration')


@admin.register(Vulnerability)
class VulnerabilityAdmin(admin.ModelAdmin):
    list_display = (
        'id', 'title', 'severity', 'risk_score',
        'risk_level', 'status', 'assigned_to', 'due_date'
    )
    search_fields = ('title',)
    list_filter = ('severity', 'risk_level', 'status')


@admin.register(RemediationTask)
class RemediationTaskAdmin(admin.ModelAdmin):
    list_display = ('id', 'title', 'vulnerability', 'assigned_to', 'status', 'due_date')
    search_fields = ('title',)
    list_filter = ('status',)


@admin.register(AIAnalysis)
class AIAnalysisAdmin(admin.ModelAdmin):
    list_display = ('id', 'vulnerability', 'provider', 'model_name', 'generated_by', 'created_at')


@admin.register(Notification)
class NotificationAdmin(admin.ModelAdmin):
    list_display = ('id', 'recipient', 'notification_type', 'title', 'is_read', 'created_at')
    list_filter = ('notification_type', 'is_read')


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('id', 'actor', 'action', 'entity_type', 'entity_id', 'created_at')
    search_fields = ('action', 'entity_type', 'entity_id')