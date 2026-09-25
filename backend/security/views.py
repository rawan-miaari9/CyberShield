import datetime

from django.contrib.auth.models import User
from django.db.models import Count, ProtectedError, Q

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response

from accounts.permissions import IsAdministratorOrSecurityAnalyst

from .models import AIAnalysis, Asset, AuditLog, Notification, RemediationTask, ScannerIntegration, SecurityFinding, Vulnerability
from .serializers import (
    AIAnalysisSerializer,
    AssetSerializer,
    AuditLogSerializer,
    NotificationSerializer,
    RemediationTaskSerializer,
    SecurityFindingSerializer,
    VulnerabilitySerializer,
)
from .ai_service import MODEL_NAME, PROVIDER_NAME, analyze_vulnerability
from .workflow import (
    analyst_user_ids,
    is_analyst,
    notify,
    notify_many,
    write_audit,
)

from .zap_service import test_zap_connection, sync_zap_findings, start_zap_spider, get_zap_spider_status

class AssetViewSet(viewsets.ModelViewSet):
    serializer_class = AssetSerializer
    permission_classes = [IsAuthenticated]

    def get_permissions(self):
        # Reads stay open to any authenticated role (assignment dropdown,
        # asset pages, ZAP target selector). Writes are analyst-only, like
        # the assign / due-date / verify actions below.
        if self.action in ('create', 'update', 'partial_update', 'destroy'):
            return [IsAdministratorOrSecurityAnalyst()]
        return [IsAuthenticated()]

    def destroy(self, request, *args, **kwargs):
        # Assets with security history are PROTECTed at the model level:
        # never cascade. Translate the raw ProtectedError into a clear
        # 409 so the UI can explain why the asset stays put.
        instance = self.get_object()
        try:
            return super().destroy(request, *args, **kwargs)
        except ProtectedError:
            linked = instance.findings.count()
            return Response(
                {'error': (
                    'Cannot delete this asset because it has linked security '
                    f'findings ({linked}). Preserve or reassign its security '
                    'history before deleting it.'
                )},
                status=status.HTTP_409_CONFLICT
            )

    def get_queryset(self):
        # Day 9 Task 6: per-asset aggregates in the same query (no N+1).
        # Open = vulnerability status NOT IN (VERIFIED, CLOSED), matching
        # the established lifecycle definition used across the frontend.
        return Asset.objects.annotate(
            finding_count=Count('findings', distinct=True),
            open_vulnerability_count=Count(
                'findings__vulnerability',
                filter=~Q(
                    findings__vulnerability__status__in=['VERIFIED', 'CLOSED']
                ),
                distinct=True,
            ),
        ).all().order_by('-created_at')


class FindingsPagination(PageNumberPagination):
    """Day 9 Task 5: server-side pagination scoped to findings only.

    Findings carry large text/JSON fields (description, evidence, raw_data)
    and grow with every ZAP sync, so an unbounded list response times out.
    Other endpoints stay unpaginated so existing array consumers keep working.
    """
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


class SecurityFindingViewSet(viewsets.ModelViewSet):
    serializer_class = SecurityFindingSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = FindingsPagination

    def get_queryset(self):
        # select_related: the list serializer emits FK ids only, but the
        # joins are near-free and keep any future nested use from going N+1.
        qs = SecurityFinding.objects.select_related(
            'integration', 'asset'
        ).all().order_by('-imported_at')
        params = self.request.query_params
        # ?status= — accept backend UPPERCASE and frontend Title-case;
        # frontend 'Ignored' maps to backend 'DISMISSED'.
        raw_status = (params.get('status') or '').strip()
        if raw_status and raw_status.lower() != 'all':
            u = raw_status.upper()
            if u in ('IGNORED', 'IGNORE'):
                u = 'DISMISSED'
            qs = qs.filter(status=u)
        # ?severity= — case-insensitive (frontend sends lowercase).
        raw_sev = (params.get('severity') or '').strip()
        if raw_sev and raw_sev.lower() != 'all':
            qs = qs.filter(severity__iexact=raw_sev)
        # ?search= — title / external_id / cwe_id substring, or exact id.
        raw_search = (params.get('search') or '').strip()
        if raw_search:
            q = Q(title__icontains=raw_search) | Q(
                external_id__icontains=raw_search
            ) | Q(cwe_id__icontains=raw_search)
            if raw_search.isdigit():
                q |= Q(id=int(raw_search))
            qs = qs.filter(q)
        # ?asset= — asset-scoped listing for AssetDetailPage (paginated).
        raw_asset = (params.get('asset') or '').strip()
        if raw_asset and raw_asset.isdigit():
            qs = qs.filter(asset_id=int(raw_asset))
        return qs

    def get_permissions(self):
        # Day 5 RBAC: analyst workflow actions require Administrator or
        # Security Analyst. Reads/writes otherwise stay IsAuthenticated
        # so IT/Developer keeps read access without analyst powers.
        if self.action in ('review', 'promote', 'test_zap_connection', 'sync_zap_findings', 'start_zap_scan'):
            return [IsAdministratorOrSecurityAnalyst()]
        return [IsAuthenticated()]

    def _reject_promoted_transition(self, request, instance):
        """PROMOTED is terminal: reject any direct status edit away from it."""
        if instance.status != 'PROMOTED':
            return None
        try:
            target = request.data.get('status') if hasattr(request, 'data') else None
        except Exception:
            target = None
        if target is None or str(target).upper() == 'PROMOTED':
            return None
        return Response(
            {'error': 'This finding has already been promoted.'},
            status=status.HTTP_400_BAD_REQUEST
        )

    def update(self, request, *args, **kwargs):
        rejected = self._reject_promoted_transition(request, self.get_object())
        if rejected is not None:
            return rejected
        return super().update(request, *args, **kwargs)

    def partial_update(self, request, *args, **kwargs):
        rejected = self._reject_promoted_transition(request, self.get_object())
        if rejected is not None:
            return rejected
        return super().partial_update(request, *args, **kwargs)

    @action(detail=False, methods=['get'], url_path='stats')
    def stats(self, request):
        """GET /api/findings/stats/ — lightweight aggregate counts.

        The dashboard KPI (Open = NEW + REVIEWED) must not be derived from
        a paginated first page. A single GROUP BY query returns the totals
        without transferring hundreds of finding payloads.
        """
        rows = SecurityFinding.objects.values('status').annotate(
            n=Count('id')
        )
        counts = {row['status']: row['n'] for row in rows}
        new = counts.get('NEW', 0)
        reviewed = counts.get('REVIEWED', 0)
        promoted = counts.get('PROMOTED', 0)
        dismissed = counts.get('DISMISSED', 0)
        total = new + reviewed + promoted + dismissed
        return Response({
            'total': total,
            'open': new + reviewed,
            'new': new,
            'reviewed': reviewed,
            'promoted': promoted,
            'dismissed': dismissed,
        })


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

    @action(detail=False, methods=['post'], url_path='zap/scan')
    def start_zap_scan(self, request):
        """POST /api/findings/zap/scan/  {asset_id: <id>}.

        Administrator/Security Analyst only. The scan target is derived
        strictly from the registered Asset's URL — a client-supplied URL
        is never accepted. Starts a ZAP Spider crawl (passive discovery;
        never an Active Scan); importing results stays a separate analyst
        action via the existing zap/sync endpoint.
        """
        asset_id = request.data.get("asset_id")

        try:
            asset = Asset.objects.get(id=asset_id)
        except (Asset.DoesNotExist, ValueError, TypeError):
            return Response(
                {"error": "Asset not found."},
                status=status.HTTP_404_NOT_FOUND
            )

        target = (asset.url or "").strip()
        if not target:
            return Response(
                {"error": "Asset has no usable URL to scan."},
                status=status.HTTP_400_BAD_REQUEST
            )

        result = start_zap_spider(target)

        if not result["success"]:
            return Response(
                result,
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        return Response(
            {
                "scan_id": result["scan_id"],
                "asset_id": asset.id,
                "asset_name": asset.name,
                "target": target,
                "status": "running",
            },
            status=status.HTTP_202_ACCEPTED
        )

    @action(detail=False, methods=['get'], url_path='zap/scan-status')
    def zap_scan_status(self, request):
        """GET /api/findings/zap/scan-status/?scan_id=<id>.

        Any authenticated user may poll. Returns progress 0-100 with a
        frontend-friendly status; completed scans are NOT auto-synced.
        """
        result = get_zap_spider_status(request.query_params.get("scan_id", ""))

        if not result["success"]:
            return Response(
                result,
                status=status.HTTP_400_BAD_REQUEST
            )

        return Response(
            {
                "scan_id": result["scan_id"],
                "progress": result["progress"],
                "status": "completed" if result["progress"] >= 100 else "running",
            },
            status=status.HTTP_200_OK
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
        # Vulnerability has no Informational level (LOW is the lowest managed
        # severity). ZAP informational findings arrive as INFO, so normalize
        # to LOW here — the finding itself keeps its original INFO severity.
        severity = finding.severity
        if severity not in dict(Vulnerability.SEVERITY_CHOICES):
            severity = 'LOW'
        vulnerability = Vulnerability.objects.create(
            finding=finding,
            title=finding.title,
            description=finding.description,
            severity=severity,
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
    serializer_class = VulnerabilitySerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        # select_related('finding'): the new read-only `asset` field walks
        # finding.asset per row — join it up front instead of N+1 queries.
        return Vulnerability.objects.select_related(
            'finding'
        ).prefetch_related('ai_analyses').all().order_by('-created_at')

    def get_permissions(self):
        # Day 5 RBAC: assign / due-date / verify are analyst-only.
        # 'transition' stays IsAuthenticated: role rules are enforced
        # inside _check_lifecycle so assigned IT/Developers can advance
        # their own items while VERIFY/CLOSE stay analyst-only.
        # AI generation reaches the action as IsAuthenticated; the
        # object-level assignee rule is enforced inside
        # generate_ai_analysis (analysts + the assigned developer only).
        # Reading past analyses stays IsAuthenticated like the
        # vulnerability itself.
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

    def _sync_linked_tasks(self, vulnerability, user, event):
        """Keep linked RemediationTasks in step with the vulnerability lifecycle.

        - 'started' (ASSIGNED -> IN_PROGRESS): OPEN tasks move to
          IN_PROGRESS; when no task exists one is created IN_PROGRESS
          (assigned to the developer), so a single action starts work on
          both records.
        - 'verified' (REMEDIATED -> VERIFIED): open tasks move to COMPLETED.
        - IN_PROGRESS -> REMEDIATED deliberately touches no task:
          COMPLETED is reserved for analyst verification, so the task
          stays IN_PROGRESS (awaiting verification) meanwhile.
        """
        from django.utils import timezone
        if event == 'started':
            tasks = list(RemediationTask.objects.filter(vulnerability=vulnerability))
            if not tasks:
                task = RemediationTask.objects.create(
                    vulnerability=vulnerability,
                    title=f'Remediation for vulnerability {vulnerability.id}',
                    assigned_to=vulnerability.assigned_to,
                    status='IN_PROGRESS',
                )
                write_audit(
                    user, 'REMEDIATION_CREATED', 'RemediationTask', task.id,
                    None, {'vulnerability': vulnerability.id, 'status': task.status},
                )
            else:
                for task in tasks:
                    if task.status != 'OPEN':
                        continue
                    task.status = 'IN_PROGRESS'
                    task.save(update_fields=['status', 'updated_at'])
                    write_audit(
                        user, 'REMEDIATION_UPDATED', 'RemediationTask', task.id,
                        {'status': 'OPEN'}, {'status': task.status},
                    )
        elif event == 'verified':
            for task in RemediationTask.objects.filter(vulnerability=vulnerability):
                if task.status in ('COMPLETED', 'CANCELLED'):
                    continue
                old = task.status
                task.status = 'COMPLETED'
                if not task.completed_at:
                    task.completed_at = timezone.now()
                task.save(update_fields=['status', 'completed_at', 'updated_at'])
                write_audit(
                    user, 'REMEDIATION_UPDATED', 'RemediationTask', task.id,
                    {'status': old}, {'status': task.status},
                )

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

        # Linked remediation work completes here: COMPLETED is reserved
        # for analyst verification, so the verify action owns it.
        self._sync_linked_tasks(vulnerability, request.user, 'verified')

        # Day 6: audit + notify the assigned developer — never the actor
        # about their own action (a self-assigned analyst verifying their
        # own item is informed by the response itself, not a notification).
        write_audit(request.user, 'VULNERABILITY_STATUS_CHANGE', 'Vulnerability', vulnerability.id, 'REMEDIATED', 'VERIFIED')
        if vulnerability.assigned_to_id and vulnerability.assigned_to_id != request.user.id:
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

        # One canonical developer action drives both records: starting
        # work also moves linked OPEN tasks to IN_PROGRESS (creating one
        # when none exists). Marking REMEDIATED intentionally leaves tasks
        # IN_PROGRESS — completion happens at verification, not here.
        if target == 'IN_PROGRESS':
            self._sync_linked_tasks(vulnerability, request.user, 'started')

        # Day 6: one audit row per transition + MVP notifications.
        # Recipient rule: notify whoever must act NEXT, never the actor
        # about their own action.
        write_audit(request.user, 'VULNERABILITY_STATUS_CHANGE', 'Vulnerability', vulnerability.id, old_status, target)
        actor_id = getattr(request.user, 'id', None)
        if target == 'REMEDIATED':
            notify_many(
                [rid for rid in analyst_user_ids() if rid != actor_id], 'REMEDIATION',
                f'Vulnerability {vulnerability.id} marked REMEDIATED',
                f'{vulnerability.title} is ready for analyst verification.',
                vulnerability=vulnerability,
            )
        elif target == 'VERIFIED' and vulnerability.assigned_to_id and vulnerability.assigned_to_id != actor_id:
            notify(
                vulnerability.assigned_to_id, 'SYSTEM',
                f'Vulnerability {vulnerability.id} verified',
                f'{vulnerability.title} was verified by the analyst team.',
                vulnerability=vulnerability,
            )
        elif target == 'CLOSED':
            recipients = [rid for rid in analyst_user_ids() if rid != actor_id]
            if vulnerability.assigned_to_id and vulnerability.assigned_to_id != actor_id:
                recipients.append(vulnerability.assigned_to_id)
            notify_many(
                recipients, 'SYSTEM',
                f'Vulnerability {vulnerability.id} closed',
                f'{vulnerability.title} is now CLOSED.',
                vulnerability=vulnerability,
            )

        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)

    @action(detail=True, methods=['post'], url_path='ai-analysis')
    def generate_ai_analysis(self, request, pk=None):
        """POST /api/vulnerabilities/<id>/ai-analysis/.

        Day 8: explicitly-requested Gemini guidance only (never automatic).
        On success persists one AIAnalysis row (history is append-only);
        on provider failure returns an error with no DB write and no
        lifecycle change. Administrator / Security Analyst, or the
        IT/Developer the vulnerability is assigned to; anyone else gets
        403 without the generation service being called.
        """
        vulnerability = self.get_object()

        role = self._caller_role(request.user)
        is_analyst = role in ('Administrator', 'Security Analyst')
        assigned_id = vulnerability.assigned_to_id
        is_assignee = (
            assigned_id is not None
            and getattr(request.user, 'id', None) is not None
            and int(assigned_id) == int(request.user.id)
        )
        if not (is_analyst or is_assignee):
            return Response(
                {'error': 'Only the assigned user, Security Analyst or Administrator can generate AI analysis.'},
                status=status.HTTP_403_FORBIDDEN
            )

        result = analyze_vulnerability(vulnerability)
        if not result.get('success'):
            return Response(
                {'error': result.get('error') or 'AI generation failed. Please try again later.'},
                status=status.HTTP_503_SERVICE_UNAVAILABLE
            )

        analysis = result.get('analysis') or {}
        required = ('explanation', 'potential_impact', 'remediation_steps', 'verification_steps')
        if any(not str(analysis.get(field) or '').strip() for field in required):
            return Response(
                {'error': 'AI service returned an incomplete response. Please try again later.'},
                status=status.HTTP_502_BAD_GATEWAY
            )

        record = AIAnalysis.objects.create(
            vulnerability=vulnerability,
            explanation=analysis['explanation'],
            potential_impact=analysis['potential_impact'],
            remediation_steps=analysis['remediation_steps'],
            verification_steps=analysis['verification_steps'],
            provider=PROVIDER_NAME,
            model_name=MODEL_NAME,
            generated_by=request.user if getattr(request.user, 'is_authenticated', False) else None,
        )

        # Day 8: audit through the existing mechanism (single record).
        write_audit(
            request.user, 'AI_ANALYSIS_GENERATED', 'AIAnalysis', record.id,
            None, {'vulnerability': vulnerability.id, 'provider': PROVIDER_NAME, 'model': MODEL_NAME},
        )

        return Response(
            AIAnalysisSerializer(record).data,
            status=status.HTTP_201_CREATED
        )

    @action(detail=True, methods=['get'], url_path='ai-analyses')
    def list_ai_analyses(self, request, pk=None):
        """GET /api/vulnerabilities/<id>/ai-analyses/.

        Past guidance stays retrievable so a page reload never loses it.
        (The vulnerability detail payload also nests ai_analyses.)
        """
        vulnerability = self.get_object()
        records = AIAnalysis.objects.filter(
            vulnerability=vulnerability
        ).order_by('-created_at')
        return Response(AIAnalysisSerializer(records, many=True).data)


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

    serializer_class = AuditLogSerializer
    permission_classes = [IsAdministratorOrSecurityAnalyst]

    def get_queryset(self):
        # actor_name is a SerializerMethodField touching obj.actor per row;
        # select_related avoids one User query per audit row (the ~2s load).
        return AuditLog.objects.select_related('actor').all().order_by(
            '-created_at'
        )