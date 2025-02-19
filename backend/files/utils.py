# In files/utils.py (or files/views.py)

from .models import AuditLog

def log_audit_event(user, action_type, file=None, details=None, ip_address=None):
    AuditLog.objects.create(
        user=user,
        action_type=action_type,
        file=file,
        details=details,
        ip_address=ip_address
    )