import datetime

from django.contrib.auth.models import User

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response

from accounts.permissions import IsAdministratorOrSecurityAnalyst

from .models import Asset, AuditLog, Notification, RemediationTask, ScannerIntegration, SecurityFinding, Vulnerability
from .serializers import (
    AssetSerializer,
    AuditLogSerializer,
    NotificationSerializer,
    RemediationTaskSerializer,
    SecurityFindingSerializer,
    VulnerabilitySerializer,
)
from .workflow import (
    analyst_user_ids,
    is_analyst,
    notify,
    notify_many,
    write_audit,
)

from .zap_service import test_zap_connection, sync_zap_findings

class AssetViewSet(viewsets.ModelViewSet):
    queryset = Asset.objects.all().order_by('-created_at')
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]


class SecurityFindingViewSet(viewsets.ModelViewSet):
    queryset = SecurityFinding.objects.all().order_by('-imported_at')
    serializer_class = SecurityFindingSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        # Day 5 RBAC: analyst workflow actions require Administrator or
        # Security Analyst. Reads/writes otherwise stay IsAuthenticated
        # so IT/Developer keeps read access without analyst powers.
        if self.action in ('review', 'promote', 'test_zap_connection', 'sync_zap_findings'):
            return [IsAdministratorOrSecurityAnalyst()]
        return [IsAuthenticated()]


    @action(detail=False, methods=['get'], url_path='zap/test-connection')
    def test_zap_connection(self, request):
        result = test_zap_connection()

        if result['success']:
            return Response(result, status=status.HTTP_200_OK)

        return Response(
            result,
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )


    @action(detail=False, methods=['post'], url_path='zap/sync')
    def sync_zap_findings(self, request):
        integration = ScannerIntegration.objects.filter(
            scanner_type='ZAP',
            is_enabled=True
        ).first()

        if not integration:
            return Response(
                {"error": "No enabled ZAP integration found."},
                status=status.HTTP_400_BAD_REQUEST
            )

        asset_id = request.data.get("asset_id")

        try:
            asset = Asset.objects.get(id=asset_id)
        except Asset.DoesNotExist:
            return Response(
                {"error": "Asset not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        result = sync_zap_findings(integration, asset)

        if result["success"]:
            return Response(result, status=status.HTTP_200_OK)

        return Response(
            result,
            status=status.HTTP_503_SERVICE_UNAVAILABLE
        )
        
    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        finding = self.get_object()
        if finding.status == 'PROMOTED':
            return Response(
                {'error': 'This finding has already been promoted.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        old_status = finding.status
        finding.status = 'REVIEWED'
        finding.save()

    
        write_audit(request.user, 'FINDING_REVIEWED', 'SecurityFinding', finding.id, old_status, 'REVIEWED')

        serializer = self.get_serializer(finding)
        return Response(serializer.data)
    @action(detail=True, methods=['post'])
    def promote(self, request, pk=None):
        finding = self.get_object()

        impact = request.data.get('impact')
        likelihood = request.data.get('likelihood')
        if impact is None or likelihood is None:
            return Response(
                {'error': 'Impact and likelihood are required.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            impact = int(impact)
            likelihood = int(likelihood)
        except (TypeError, ValueError):
            return Response(
                {'error': 'Impact and likelihood must be numbers.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if not (1 <= impact <= 5) or not (1 <= likelihood <= 5):
            return Response(
                {'error': 'Impact and likelihood must be between 1 and 5.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        
        if Vulnerability.objects.filter(finding=finding).exists():
            return Response(
                {'error': 'This finding has already been promoted to a vulnerability.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        # Day 5 workflow rule: only REVIEWED findings may be promoted.
        # Keeps NEW -> PROMOTED direct promotion rejected, while
        # NEW -> REVIEWED -> PROMOTED still succeeds.
        if finding.status != 'REVIEWED':
            return Response(
                {'error': 'Only REVIEWED findings can be promoted.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        vulnerability = Vulnerability.objects.create(
            finding=finding,
            title=finding.title,
            description=finding.description,
            severity=finding.severity,
            impact=impact,
            likelihood=likelihood,
        )

        finding.status = 'PROMOTED'
        finding.save()

        # Day 6: server-side audit (single record for this action).
        write_audit(request.user, 'FINDING_PROMOTED', 'SecurityFinding', finding.id, 'REVIEWED', f'PROMOTED -> Vulnerability {vulnerability.id}')

        serializer = VulnerabilitySerializer(vulnerability)

        return Response(
            serializer.data,
            status=status.HTTP_201_CREATED
        )

class VulnerabilityViewSet(viewsets.ModelViewSet):
    queryset = Vulnerability.objects.all().order_by('-created_at')
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        # Day 5 RBAC: assign / due-date / verify are analyst-only.
        # 'transition' stays IsAuthenticated: role rules are enforced
        # inside _check_lifecycle so assigned IT/Developers can advance
        # their own items while VERIFY/CLOSE stay analyst-only.
        if self.action in ('assign', 'set_due_date', 'verify'):
            return [IsAdministratorOrSecurityAnalyst()]
        return [IsAuthenticated()]

    # Strict lifecycle: NEW -> ASSIGNED -> IN_PROGRESS -> REMEDIATED
    # -> VERIFIED -> CLOSED. Single forward step only, no skips/backwards.
    LIFECYCLE = ['NEW', 'ASSIGNED', 'IN_PROGRESS', 'REMEDIATED', 'VERIFIED', 'CLOSED']

    def _caller_role(self, user):
        try:
            return user.profile.role.name
        except Exception:
            return None

    def _check_lifecycle(self, vulnerability, target, user):
        """Return None if allowed, else an error Response.

        - target must be the immediate next stage (no skips/backwards).
        - NEW -> ASSIGNED only via the assign action.
        - ASSIGNED -> IN_PROGRESS and IN_PROGRESS -> REMEDIATED by the
          assigned user (any role, i.e. the IT/Developer) or Analyst/Admin.
        - REMEDIATED -> VERIFIED and VERIFIED -> CLOSED by Analyst/Admin.
        """
        order = self.LIFECYCLE
        current = vulnerability.status
        if target not in order:
            return Response(
                {'error': f'Invalid status: {target}.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if current not in order or order.index(target) != order.index(current) + 1:
            return Response(
                {'error': f'Invalid transition: {current} -> {target}. Only the next lifecycle stage is allowed.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        if current == 'NEW':
            return Response(
                {'error': 'NEW vulnerabilities move to ASSIGNED through assignment.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        role = self._caller_role(user)
        is_analyst = role in ('Administrator', 'Security Analyst')
        if target in ('IN_PROGRESS', 'REMEDIATED'):
            assigned_id = vulnerability.assigned_to_id
            is_assignee = (
                assigned_id is not None
                and getattr(user, 'id', None) is not None
                and int(assigned_id) == int(user.id)
            )
            if not (is_assignee or is_analyst):
                return Response(
                    {'error': 'Only the assigned user, Security Analyst or Administrator can perform this transition.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            return None
        if target in ('VERIFIED', 'CLOSED'):
            if not is_analyst:
                return Response(
                    {'error': 'You do not have permission to perform this action.'},
                    status=status.HTTP_403_FORBIDDEN
                )
            return None
        return None

    def _reject_invalid_direct_status(self, request, instance=None):
        """Block bypass of the lifecycle via generic PUT/PATCH status edits."""
        try:
            target = (request.data.get('status') if hasattr(request, 'data') else None)
        except Exception:
            target = None
        if target is None or (instance is not None and target == instance.status):
            return None
        return self._check_lifecycle(instance, target, request.user)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        rejected = self._reject_invalid_direct_status(request, instance)
        if rejected is not None:
            return rejected
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        instance = self.get_object()
        rejected = self._reject_invalid_direct_status(request, instance)
        if rejected is not None:
            return rejected
        return super().partial_update(request, *args, **kwargs)

    @action(detail=True, methods=['post'], url_path='assign')
    def assign(self, request, pk=None):
        """POST /api/vulnerabilities/<id>/assign/  {assigned_to: <userId>}.

        Day 5 MVP: validates the user, assigns, moves NEW -> ASSIGNED,
        leaves all other statuses untouched. Risk fields are recomputed
        by save() from unchanged impact/likelihood, so they do not change.
        """
        vulnerability = self.get_object()

        user_id = request.data.get('assigned_to')
        if user_id is None or user_id == '':
            return Response(
                {'error': 'assigned_to is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            assignee = User.objects.get(pk=user_id)
        except (User.DoesNotExist, ValueError, TypeError):
            return Response(
                {'error': 'User does not exist.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        old_assignee = vulnerability.assigned_to_id
        old_status = vulnerability.status
        vulnerability.assigned_to = assignee
        if vulnerability.status == 'NEW':
            vulnerability.status = 'ASSIGNED'
        vulnerability.save()

        # Day 6: server-side audit + notify the assigned developer.
        write_audit(
            request.user, 'VULNERABILITY_ASSIGNED', 'Vulnerability', vulnerability.id,
            {'assigned_to': old_assignee, 'status': old_status},
            {'assigned_to': assignee.id, 'status': vulnerability.status},
        )
        notify(
            assignee.id, 'ASSIGNMENT',
            f'Vulnerability {vulnerability.id} assigned to you',
            f'{vulnerability.title} is now assigned to {assignee.username}.',
            vulnerability=vulnerability,
        )

        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='due-date')
    def set_due_date(self, request, pk=None):
        """POST /api/vulnerabilities/<id>/due-date/  {due_date: YYYY-MM-DD}.

        Validates the date via model/serializer validation; invalid dates
        return HTTP 400. Does not touch impact/likelihood, so risk is
        unchanged (save() recomputes the identical score).
        """
        vulnerability = self.get_object()

        due_date = request.data.get('due_date')
        if not due_date:
            return Response(
                {'error': 'due_date is required (YYYY-MM-DD).'},
                status=status.HTTP_400_BAD_REQUEST
            )
        try:
            parsed = datetime.date.fromisoformat(str(due_date))
        except (ValueError, TypeError):
            return Response(
                {'error': 'Invalid due date. Use YYYY-MM-DD.'},
                status=status.HTTP_400_BAD_REQUEST
            )

        old_due = vulnerability.due_date.isoformat() if vulnerability.due_date else None
        vulnerability.due_date = parsed
        vulnerability.save()

        # Day 6: server-side audit (single record for this action).
        write_audit(
            request.user, 'VULNERABILITY_DUE_DATE', 'Vulnerability', vulnerability.id,
            old_due, parsed.isoformat(),
        )

        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='verify')
    def verify(self, request, pk=None):
        """POST /api/vulnerabilities/<id>/verify/.

        Kept for the Mark-verified button: REMEDIATED -> VERIFIED,
        Administrator/Security Analyst only.
        """
        vulnerability = self.get_object()
        rejected = self._check_lifecycle(vulnerability, 'VERIFIED', request.user)
        # get_permissions already restricts to Analyst/Admin; the check
        # above additionally enforces the REMEDIATED-only stage rule.
        if rejected is not None:
            return rejected
        vulnerability.status = 'VERIFIED'
        vulnerability.save()

        # Day 6: audit + notify the assigned developer.
        write_audit(request.user, 'VULNERABILITY_STATUS_CHANGE', 'Vulnerability', vulnerability.id, 'REMEDIATED', 'VERIFIED')
        if vulnerability.assigned_to_id:
            notify(
                vulnerability.assigned_to_id, 'SYSTEM',
                f'Vulnerability {vulnerability.id} verified',
                f'{vulnerability.title} was verified by the analyst team.',
                vulnerability=vulnerability,
            )

        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='transition')
    def transition(self, request, pk=None):
        """POST /api/vulnerabilities/<id>/transition/  {status: <next>}.

        Single strict forward step persisted to the database. Role rules
        enforced in _check_lifecycle; risk untouched (save() recomputes
        the identical score from unchanged impact/likelihood).
        """
        vulnerability = self.get_object()
        target = request.data.get('status')
        if not target:
            return Response(
                {'error': 'status is required.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        rejected = self._check_lifecycle(vulnerability, target, request.user)
        if rejected is not None:
            return rejected
        old_status = vulnerability.status
        vulnerability.status = target
        vulnerability.save()

        # Day 6: one audit row per transition + MVP notifications.
        write_audit(request.user, 'VULNERABILITY_STATUS_CHANGE', 'Vulnerability', vulnerability.id, old_status, target)
        if target == 'REMEDIATED':
            notify_many(
                analyst_user_ids(), 'REMEDIATION',
                f'Vulnerability {vulnerability.id} marked REMEDIATED',
                f'{vulnerability.title} is ready for analyst verification.',
                vulnerability=vulnerability,
            )
        elif target == 'VERIFIED' and vulnerability.assigned_to_id:
            notify(
                vulnerability.assigned_to_id, 'SYSTEM',
                f'Vulnerability {vulnerability.id} verified',
                f'{vulnerability.title} was verified by the analyst team.',
                vulnerability=vulnerability,
            )
        elif target == 'CLOSED':
            recipients = list(analyst_user_ids())
            if vulnerability.assigned_to_id:
                recipients.append(vulnerability.assigned_to_id)
            notify_many(
                recipients, 'SYSTEM',
                f'Vulnerability {vulnerability.id} closed',
                f'{vulnerability.title} is now CLOSED.',
                vulnerability=vulnerability,
            )

        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)


class RemediationViewSet(viewsets.ModelViewSet):
    """Day 6: real remediation workflow on the existing RemediationTask model.

    No second lifecycle: the vulnerability lifecycle stays authoritative.
    Developers may create/update work only for vulnerabilities assigned to
    them; Analyst/Administrator may view and edit anything.
    """

    queryset = RemediationTask.objects.all().order_by('-updated_at')
    serializer_class = RemediationTaskSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        if is_analyst(self.request.user):
            base = qs
        else:
            base = qs.filter(vulnerability__assigned_to=self.request.user)
        vuln_id = self.request.query_params.get('vulnerability')
        if vuln_id:
            base = base.filter(vulnerability_id=vuln_id)
        return base

    def _can_write(self, vulnerability):
        if is_analyst(self.request.user):
            return True
        return (
            vulnerability.assigned_to_id is not None
            and int(vulnerability.assigned_to_id) == int(self.request.user.id)
        )

    def perform_create(self, serializer):
        vulnerability = serializer.validated_data.get('vulnerability')
        if vulnerability is None or not self._can_write(vulnerability):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied('Only the assigned user, Security Analyst or Administrator can record remediation work.')
        if not serializer.validated_data.get('assigned_to'):
            serializer.validated_data['assigned_to'] = vulnerability.assigned_to
        instance = serializer.save()
        if instance.status == 'COMPLETED' and not instance.completed_at:
            from django.utils import timezone
            instance.completed_at = timezone.now()
            instance.save(update_fields=['completed_at', 'updated_at'])
        write_audit(
            self.request.user, 'REMEDIATION_CREATED', 'RemediationTask', instance.id,
            None, {'vulnerability': vulnerability.id, 'status': instance.status},
        )

    def perform_update(self, serializer):
        instance = self.get_object()
        if not self._can_write(instance.vulnerability):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied('Only the assigned user, Security Analyst or Administrator can update remediation work.')
        old = {'notes': instance.notes, 'description': instance.description, 'status': instance.status}
        updated = serializer.save()
        if updated.status == 'COMPLETED' and not updated.completed_at:
            from django.utils import timezone
            updated.completed_at = timezone.now()
            updated.save(update_fields=['completed_at', 'updated_at'])
        write_audit(
            self.request.user, 'REMEDIATION_UPDATED', 'RemediationTask', updated.id,
            old,
            {'notes': updated.notes, 'description': updated.description, 'status': updated.status},
        )


class NotificationViewSet(viewsets.ModelViewSet):
    """Day 6: persisted notifications. Server-created only (no POST/DELETE).

    Users see their own notifications; Analyst/Administrator see all.
    Only the is_read flag is writable, and only on your own rows.
    """

    queryset = Notification.objects.all().order_by('-created_at')
    serializer_class = NotificationSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        qs = super().get_queryset()
        if is_analyst(self.request.user):
            return qs
        return qs.filter(recipient=self.request.user)

    def create(self, request, *args, **kwargs):
        return Response(
            {'error': 'Notifications are created by the server.'},
            status=status.HTTP_403_FORBIDDEN
        )

    def destroy(self, request, *args, **kwargs):
        return Response(
            {'error': 'Notifications cannot be deleted.'},
            status=status.HTTP_403_FORBIDDEN
        )

    def perform_update(self, serializer):
        instance = self.get_object()
        if int(instance.recipient_id) != int(self.request.user.id) and not is_analyst(self.request.user):
            from rest_framework.exceptions import PermissionDenied
            raise PermissionDenied('You can only update your own notifications.')
        serializer.save(vulnerability=instance.vulnerability, recipient=instance.recipient)

    @action(detail=False, methods=['post'], url_path='mark-all-read')
    def mark_all_read(self, request):
        updated = Notification.objects.filter(
            recipient=request.user, is_read=False
        ).update(is_read=True)
        return Response({'marked': updated})

    @action(detail=True, methods=['post'], url_path='read')
    def mark_read(self, request, pk=None):
        notification = self.get_object()
        if int(notification.recipient_id) != int(request.user.id) and not is_analyst(request.user):
            return Response(
                {'error': 'You can only update your own notifications.'},
                status=status.HTTP_403_FORBIDDEN
            )
        notification.is_read = True
        notification.save(update_fields=['is_read'])
        return Response(self.get_serializer(notification).data)


class AuditLogViewSet(viewsets.ReadOnlyModelViewSet):
    """Read-only audit trail: Administrator/Security Analyst only.

    IT/Developer is denied at the API (HTTP 403), not just hidden in UI.
    """

    queryset = AuditLog.objects.all().order_by('-created_at')
    serializer_class = AuditLogSerializer
    permission_classes = [IsAdministratorOrSecurityAnalyst]