import redis.connection as _rc

_OrigConnection = _rc.Connection
_OrigSSLConnection = _rc.SSLConnection


class _RESP2Connection(_OrigConnection):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("protocol", 2)
        super().__init__(*args, **kwargs)


class _RESP2SSLConnection(_OrigSSLConnection):
    def __init__(self, *args, **kwargs):
        kwargs.setdefault("protocol", 2)
        super().__init__(*args, **kwargs)


_rc.Connection = _RESP2Connection
_rc.SSLConnection = _RESP2SSLConnection

from celery import Celery

from app.core.config import settings


celery_app = Celery(
    "mailox",
    broker=settings.CELERY_BROKER_URL,
    backend=settings.CELERY_RESULT_BACKEND,
    include=["app.worker.tasks"],
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_soft_time_limit=settings.SCAN_TASK_TIMEOUT_SECONDS,
    task_time_limit=settings.SCAN_TASK_TIMEOUT_SECONDS + 30,
    beat_schedule={
        "recover-stalled-scans": {
            "task": "mailox.recover_stalled_scans",
            "schedule": 60.0,
        },
        "check-monitoring-schedules": {
            "task": "mailox.check_monitoring_schedules",
            "schedule": 60.0,
        },
        "intel-sync-nvd": {
            "task": "intel.sync_nvd",
            "schedule": 86400.0,  # 24 hours
        },
        "intel-sync-cisa-kev": {
            "task": "intel.sync_cisa_kev",
            "schedule": 43200.0,  # 12 hours
        },
        "intel-sync-osv": {
            "task": "intel.sync_osv",
            "schedule": 86400.0,  # 24 hours
        },
        "run-scheduled-scans": {
            "task": "mailox.run_scheduled_scans",
            "schedule": 3600.0,  # every hour
        },
    },
)
