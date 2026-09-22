from rest_framework import serializers
from .models import AIAnalysis, Asset, AuditLog, Notification, RemediationTask, SecurityFinding, Vulnerability


class AssetSerializer(serializers.ModelSerializer):
    class Meta:
        model = Asset
        fields = [
            'id',
            'name',
            'asset_type',
            'hostname',
            'ip_address',
            'url',
            'criticality',
            'description',
            'is_active',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'created_at',
            'updated_at',
        ]


class SecurityFindingSerializer(serializers.ModelSerializer):

    class Meta:
        model = SecurityFinding

        fields = [
            'id',
            'integration',
            'asset',
            'external_id',
            'fingerprint',
            'title',
            'description',
            'severity',
            'confidence',
            'cwe_id',
            'evidence',
            'source_url',
            'status',
            'raw_data',
            'imported_at',
            'updated_at',
        ]

        read_only_fields = [
            'id',
            'imported_at',
            'updated_at',
        ]


class AIAnalysisSerializer(serializers.ModelSerializer):
    """Day 8: persisted Gemini guidance (server-created only, read via API)."""

    generated_by_name = serializers.SerializerMethodField()

    class Meta:
        model = AIAnalysis
        fields = [
            'id',
            'vulnerability',
            'explanation',
            'potential_impact',
            'remediation_steps',
            'verification_steps',
            'provider',
            'model_name',
            'generated_by',
            'generated_by_name',
            'created_at',
        ]
        read_only_fields = fields

    def get_generated_by_name(self, obj):
        if obj.generated_by is None:
            return None
        return obj.generated_by.username or obj.generated_by.email or f'User {obj.generated_by_id}'


class VulnerabilitySerializer(serializers.ModelSerializer):

    ai_analyses = AIAnalysisSerializer(many=True, read_only=True)

    class Meta:
        model = Vulnerability

        fields = [
            'id',
            'finding',
            'title',
            'description',
            'severity',
            'impact',
            'likelihood',
            'risk_score',
            'risk_level',
            'status',
            'assigned_to',
            'due_date',
            'remediation_guidance',
            'ai_analyses',
            'created_at',
            'updated_at',
        ]

        read_only_fields = [
            'id',
            'risk_score',
            'risk_level',
            'ai_analyses',
            'created_at',
            'updated_at',
        ]


class RemediationTaskSerializer(serializers.ModelSerializer):
    """Day 6: exposes the existing RemediationTask model (no model change)."""

    class Meta:
        model = RemediationTask
        fields = [
            'id',
            'vulnerability',
            'title',
            'description',
            'assigned_to',
            'status',
            'due_date',
            'notes',
            'completed_at',
            'created_at',
            'updated_at',
        ]
        read_only_fields = [
            'id',
            'created_at',
            'updated_at',
        ]


class NotificationSerializer(serializers.ModelSerializer):
    """Day 6: safe fields only — recipient/vulnerability are IDs, no secrets."""

    class Meta:
        model = Notification
        fields = [
            'id',
            'recipient',
            'notification_type',
            'title',
            'message',
            'vulnerability',
            'is_read',
            'created_at',
        ]
        read_only_fields = [
            'id',
            'created_at',
        ]


class AuditLogSerializer(serializers.ModelSerializer):
    """Day 6: read-only audit trail (created server-side only)."""

    actor_name = serializers.SerializerMethodField()

    class Meta:
        model = AuditLog
        fields = [
            'id',
            'actor',
            'actor_name',
            'action',
            'entity_type',
            'entity_id',
            'old_value',
            'new_value',
            'created_at',
        ]
        read_only_fields = fields

    def get_actor_name(self, obj):
        if obj.actor is None:
            return 'system'
        return obj.actor.username or obj.actor.email or f'User {obj.actor_id}'