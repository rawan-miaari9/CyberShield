"""Day 6 shared helpers: server-side audit + notifications.

Kept in the existing security app (no new app, no model changes).
All workflow writes go through these so each action records exactly one
audit row and the specified notifications — never duplicated.
"""

from .models import AuditLog, Notification

ANALYST_ROLES = ('Administrator', 'Security Analyst')


def caller_role(user):
    try:
        return user.profile.role.name
    except Exception:
        return None


def is_analyst(user):
    return caller_role(user) in ANALYST_ROLES


def analyst_user_ids():
    """IDs of users who should receive analyst notifications (MVP)."""
    from django.contrib.auth.models import User

    return list(
        User.objects.filter(
            profile__role__name__in=list(ANALYST_ROLES)
        ).values_list('id', flat=True)
    )


def write_audit(actor, action, entity_type, entity_id, old_value=None, new_value=None):
    """Persist one audit record (best-effort: never breaks the workflow)."""
    try:
        return AuditLog.objects.create(
            actor=actor if getattr(actor, 'is_authenticated', False) else None,
            action=action,
            entity_type=entity_type,
            entity_id=str(entity_id),
            old_value=old_value,
            new_value=new_value,
        )
    except Exception:
        return None


NOTIFY_DEDUP_SECONDS = 60


def _recent_duplicate(recipient_id, notification_type, title, message, vulnerability):
    """True if the identical notification was just created.

    Source fix for double-submit races (e.g. double-clicking a lifecycle
    button): one workflow event must yield one row per recipient even if
    the action endpoint is hit twice within the same second.
    """
    import datetime

    from django.utils import timezone

    qs = Notification.objects.filter(
        recipient_id=recipient_id,
        notification_type=notification_type,
        title=title,
        message=message,
        created_at__gte=timezone.now() - datetime.timedelta(seconds=NOTIFY_DEDUP_SECONDS),
    )
    if vulnerability is None:
        qs = qs.filter(vulnerability__isnull=True)
    else:
        qs = qs.filter(vulnerability=vulnerability)
    return qs.exists()


def notify(recipient_id, notification_type, title, message, vulnerability=None):
    """Persist one notification (best-effort, idempotent per event)."""
    try:
        if _recent_duplicate(recipient_id, notification_type, title, message, vulnerability):
            return None
        return Notification.objects.create(
            recipient_id=recipient_id,
            notification_type=notification_type,
            title=title,
            message=message,
            vulnerability=vulnerability,
        )
    except Exception:
        return None


def notify_many(recipient_ids, notification_type, title, message, vulnerability=None):
    seen = set()
    for rid in recipient_ids or []:
        if rid is None or rid in seen:
            continue
        seen.add(rid)
        notify(rid, notification_type, title, message, vulnerability)
