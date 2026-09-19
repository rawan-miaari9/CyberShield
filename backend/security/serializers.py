from rest_framework import serializers
from .models import Asset, SecurityFinding, Vulnerability


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


class VulnerabilitySerializer(serializers.ModelSerializer):

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
            'created_at',
            'updated_at',
        ]

        read_only_fields = [
            'id',
            'risk_score',
            'risk_level',
            'created_at',
            'updated_at',
        ]