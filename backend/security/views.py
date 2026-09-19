import datetime

from django.contrib.auth.models import User

from rest_framework import viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.response import Response

from accounts.permissions import IsAdministratorOrSecurityAnalyst

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

    def get_permissions(self):
        # Day 5 RBAC: analyst workflow actions require Administrator or
        # Security Analyst. Reads/writes otherwise stay IsAuthenticated
        # so IT/Developer keeps read access without analyst powers.
        if self.action in ('review', 'promote'):
            return [IsAdministratorOrSecurityAnalyst()]
        return [IsAuthenticated()]

    @action(detail=True, methods=['post'])
    def review(self, request, pk=None):
        finding = self.get_object()
        if finding.status == 'PROMOTED':
            return Response(
                {'error': 'This finding has already been promoted.'},
                status=status.HTTP_400_BAD_REQUEST
            )
        finding.status = 'REVIEWED'
        finding.save()

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

        vulnerability.assigned_to = assignee
        if vulnerability.status == 'NEW':
            vulnerability.status = 'ASSIGNED'
        vulnerability.save()

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

        vulnerability.due_date = parsed
        vulnerability.save()

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
        vulnerability.status = target
        vulnerability.save()

        serializer = self.get_serializer(vulnerability)
        return Response(serializer.data)