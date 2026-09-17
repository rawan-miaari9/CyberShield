from django.db import models
from django.core.validators import MinValueValidator, MaxValueValidator


class Asset(models.Model):

    CRITICALITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    ASSET_TYPE_CHOICES = [
        ('WEB_APP', 'Web Application'),
        ('SERVER', 'Server'),
        ('NETWORK_DEVICE', 'Network Device'),
        ('OTHER', 'Other'),
    ]

    name = models.CharField(max_length=150)

    asset_type = models.CharField(
        max_length=30,
        choices=ASSET_TYPE_CHOICES
    )

    hostname = models.CharField(
        max_length=255,
        blank=True
    )

    ip_address = models.GenericIPAddressField(
        blank=True,
        null=True
    )

    url = models.URLField(
        blank=True
    )

    criticality = models.CharField(
        max_length=20,
        choices=CRITICALITY_CHOICES,
        default='MEDIUM'
    )

    description = models.TextField(blank=True)

    is_active = models.BooleanField(default=True)

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class ScannerIntegration(models.Model):

    SCANNER_TYPE_CHOICES = [
        ('ZAP', 'OWASP ZAP'),
        ('OTHER', 'Other'),
    ]

    STATUS_CHOICES = [
        ('CONNECTED', 'Connected'),
        ('DISCONNECTED', 'Disconnected'),
        ('ERROR', 'Error'),
    ]

    name = models.CharField(max_length=100)

    scanner_type = models.CharField(
        max_length=30,
        choices=SCANNER_TYPE_CHOICES,
        default='ZAP'
    )

    base_url = models.URLField()

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='DISCONNECTED'
    )

    is_enabled = models.BooleanField(default=True)

    last_sync_at = models.DateTimeField(
        blank=True,
        null=True
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.name

class SecurityFinding(models.Model):

    SEVERITY_CHOICES = [
        ('INFO', 'Informational'),
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('REVIEWED', 'Reviewed'),
        ('DISMISSED', 'Dismissed'),
        ('PROMOTED', 'Promoted to Vulnerability'),
    ]

    integration = models.ForeignKey(
        ScannerIntegration,
        on_delete=models.PROTECT,
        related_name='findings'
    )

    asset = models.ForeignKey(
        Asset,
        on_delete=models.PROTECT,
        related_name='findings'
    )

    external_id = models.CharField(
        max_length=255,
        blank=True
    )

    fingerprint = models.CharField(
        max_length=255
    )

    title = models.CharField(max_length=255)

    description = models.TextField(blank=True)

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES
    )

    confidence = models.CharField(
        max_length=50,
        blank=True
    )

    cwe_id = models.CharField(
        max_length=20,
        blank=True
    )

    evidence = models.TextField(blank=True)

    source_url = models.URLField(blank=True)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='NEW'
    )

    raw_data = models.JSONField(
        blank=True,
        null=True
    )

    imported_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [
            models.UniqueConstraint(
                fields=['integration', 'fingerprint'],
                name='unique_integration_fingerprint'
            )
        ]

    def __str__(self):
        return self.title

class Vulnerability(models.Model):
    SEVERITY_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    STATUS_CHOICES = [
        ('NEW', 'New'),
        ('ASSIGNED', 'Assigned'),
        ('IN_PROGRESS', 'In Progress'),
        ('REMEDIATED', 'Remediated'),
        ('VERIFIED', 'Verified'),
        ('CLOSED', 'Closed'),
    ]

    RISK_LEVEL_CHOICES = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]

    finding = models.OneToOneField(
        SecurityFinding,
        on_delete=models.PROTECT,
        related_name='vulnerability'
    )

    title = models.CharField(max_length=255)

    description = models.TextField(blank=True)

    severity = models.CharField(
        max_length=20,
        choices=SEVERITY_CHOICES
    )

    impact = models.PositiveSmallIntegerField(
    validators=[
        MinValueValidator(1),
        MaxValueValidator(5)
    ]
)

    likelihood = models.PositiveSmallIntegerField(
    validators=[
        MinValueValidator(1),
        MaxValueValidator(5)
    ]
)

    risk_score = models.PositiveSmallIntegerField(
    editable=False
)

    risk_level = models.CharField(
    max_length=20,
    choices=RISK_LEVEL_CHOICES,
    editable=False
)

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='NEW'
    )

    assigned_to = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='assigned_vulnerabilities'
    )

    due_date = models.DateField(
        null=True,
        blank=True
    )

    remediation_guidance = models.TextField(blank=True)

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

def save(self, *args, **kwargs):
    self.risk_score = self.impact * self.likelihood

    if self.risk_score <= 4:
        self.risk_level = 'LOW'
    elif self.risk_score <= 9:
        self.risk_level = 'MEDIUM'
    elif self.risk_score <= 16:
        self.risk_level = 'HIGH'
    else:
        self.risk_level = 'CRITICAL'

    super().save(*args, **kwargs)

def __str__(self):
    return self.title
class RemediationTask(models.Model):
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('IN_PROGRESS', 'In Progress'),
        ('COMPLETED', 'Completed'),
        ('CANCELLED', 'Cancelled'),
    ]

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.PROTECT,
        related_name='remediation_tasks'
    )

    title = models.CharField(max_length=255)

    description = models.TextField(blank=True)

    assigned_to = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='remediation_tasks'
    )

    status = models.CharField(
        max_length=20,
        choices=STATUS_CHOICES,
        default='OPEN'
    )

    due_date = models.DateField(
        null=True,
        blank=True
    )

    notes = models.TextField(blank=True)

    completed_at = models.DateTimeField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return self.title

class AIAnalysis(models.Model):
    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.PROTECT,
        related_name='ai_analyses'
    )

    explanation = models.TextField()

    potential_impact = models.TextField()

    remediation_steps = models.TextField()

    verification_steps = models.TextField()

    provider = models.CharField(
        max_length=100,
        blank=True
    )

    model_name = models.CharField(
        max_length=100,
        blank=True
    )

    generated_by = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='generated_ai_analyses'
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"AI Analysis - {self.vulnerability.title}"

class Notification(models.Model):
    TYPE_CHOICES = [
        ('ASSIGNMENT', 'Assignment'),
        ('REMEDIATION', 'Remediation'),
        ('SCANNER_SYNC', 'Scanner Sync'),
        ('SYSTEM', 'System'),
    ]

    recipient = models.ForeignKey(
        'auth.User',
        on_delete=models.CASCADE,
        related_name='notifications'
    )

    notification_type = models.CharField(
        max_length=30,
        choices=TYPE_CHOICES
    )

    title = models.CharField(max_length=255)

    message = models.TextField()

    vulnerability = models.ForeignKey(
        Vulnerability,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='notifications'
    )

    is_read = models.BooleanField(default=False)

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class AuditLog(models.Model):
    actor = models.ForeignKey(
        'auth.User',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='audit_logs'
    )

    action = models.CharField(max_length=100)

    entity_type = models.CharField(max_length=100)

    entity_id = models.CharField(max_length=100)

    old_value = models.JSONField(
        null=True,
        blank=True
    )

    new_value = models.JSONField(
        null=True,
        blank=True
    )

    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action} - {self.entity_type} #{self.entity_id}"