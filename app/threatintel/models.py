"""Database models for Wazuh-TI.

``Indicator`` is the current IOC export snapshot, ``RetroJob`` is transient queue
state, and ``RetroHit`` stores durable Wazuh matches found by retro-hunting.
"""

from __future__ import annotations

from django.core.exceptions import ValidationError
from django.db import OperationalError, ProgrammingError, models
from django.utils import timezone


class IocKind(models.TextChoices):
    IP = "ip", "IP address"
    DOMAIN = "domain", "Domain"
    HASH = "hash", "File hash"


class RunStatus(models.TextChoices):
    PENDING = "pending", "Pending"
    RUNNING = "running", "Running"
    SUCCESS = "success", "Success"
    FAILED = "failed", "Failed"
    SKIPPED = "skipped", "Skipped"


class TiConfiguration(models.Model):
    """Singleton runtime configuration edited from Django Admin."""

    taxii_url = models.URLField(blank=True, help_text="OpenCTI TAXII collection endpoint URL.")
    request_timeout_seconds = models.PositiveIntegerField(default=30)
    ioc_tag = models.CharField(max_length=64, default="opencti")
    export_api_token = models.CharField(
        max_length=255,
        default="change-me",
        help_text="Bearer token required by the Wazuh manager fetch script. Change this before production.",
    )

    fetch_enabled = models.BooleanField(default=True)
    fetch_cron_minute = models.CharField(max_length=64, default="0")
    fetch_cron_hour = models.CharField(max_length=64, default="3,15", help_text="Default: twice per day.")

    tranco_enabled = models.BooleanField(default=True)
    tranco_dir = models.CharField(max_length=512, default="/var/lib/wazuh-ti/tranco")
    tranco_max_age_days = models.PositiveIntegerField(default=14)
    tranco_download_retries = models.PositiveIntegerField(default=3)
    tranco_retry_sleep_seconds = models.PositiveIntegerField(default=5)

    retrohunt_enabled = models.BooleanField(default=True)
    retrohunt_queue_existing_on_first_run = models.BooleanField(
        default=False,
        help_text="False means first TAXII import creates the baseline but does not retro-hunt the whole existing inventory.",
    )
    opencti_initial_snapshot_seen = models.BooleanField(
        default=False,
        help_text=(
            "Internal flag. True after the first successful OpenCTI TAXII snapshot. "
            "Used to avoid retro-hunting the whole existing OpenCTI baseline on first import."
        ),
    )
    retrohunt_interval_minutes = models.PositiveIntegerField(default=30)
    retrohunt_index = models.CharField(max_length=255, default="wazuh-alerts-*")
    retrohunt_lookback_days = models.PositiveIntegerField(default=90)
    retrohunt_batches_per_run = models.PositiveIntegerField(default=4)
    retrohunt_iocs_per_batch = models.PositiveIntegerField(default=250)
    retrohunt_hash_iocs_per_batch = models.PositiveIntegerField(default=10)
    retrohunt_page_size = models.PositiveIntegerField(default=100)
    retrohunt_max_alerts_per_run = models.PositiveIntegerField(default=250)
    retrohunt_query_delay_seconds = models.PositiveIntegerField(default=2)
    retrohunt_hash_search_enabled = models.BooleanField(default=True)

    wazuh_indexer_url = models.URLField(default="https://127.0.0.1:9200")
    wazuh_indexer_username = models.CharField(max_length=255, blank=True)
    wazuh_indexer_password = models.CharField(max_length=255, blank=True)
    wazuh_indexer_verify_tls = models.BooleanField(default=False)
    wazuh_indexer_ca_bundle = models.CharField(max_length=512, blank=True)

    exact_ip_fields = models.TextField(
        default="data.src_ip\ndata.dest_ip\ndata.win.eventdata.sourceIp\ndata.win.eventdata.destinationIp"
    )
    exact_domain_fields = models.TextField(
        default="data.dns.rrname\ndata.tls.sni\ndata.http.hostname\ndata.win.eventdata.queryName"
    )
    hash_fields = models.TextField(default="data.win.eventdata.hashes\ndata.win.eventdata.hash")

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "TI configuration"
        verbose_name_plural = "TI configuration"

    def __str__(self) -> str:
        return "Wazuh-TI configuration"

    def clean(self) -> None:
        if self.fetch_enabled and not self.taxii_url:
            raise ValidationError("TAXII URL is required when scheduled fetch is enabled.")

        positive_fields = {
            "request_timeout_seconds": self.request_timeout_seconds,
            "tranco_max_age_days": self.tranco_max_age_days,
            "tranco_download_retries": self.tranco_download_retries,
            "retrohunt_interval_minutes": self.retrohunt_interval_minutes,
            "retrohunt_lookback_days": self.retrohunt_lookback_days,
            "retrohunt_batches_per_run": self.retrohunt_batches_per_run,
            "retrohunt_iocs_per_batch": self.retrohunt_iocs_per_batch,
            "retrohunt_hash_iocs_per_batch": self.retrohunt_hash_iocs_per_batch,
            "retrohunt_page_size": self.retrohunt_page_size,
            "retrohunt_max_alerts_per_run": self.retrohunt_max_alerts_per_run,
        }

        invalid = [name for name, value in positive_fields.items() if value < 1]
        if invalid:
            raise ValidationError({name: "Must be greater than zero." for name in invalid})

    def save(self, *args, **kwargs) -> None:
        # Keep exactly one runtime configuration row.
        self.pk = 1
        super().save(*args, **kwargs)
        sync_periodic_tasks_safe(self)

    @classmethod
    def load(cls) -> "TiConfiguration":
        obj, _created = cls.objects.get_or_create(pk=1)
        return obj

    def field_list(self, kind: str) -> list[str]:
        if kind == IocKind.IP:
            raw = self.exact_ip_fields
        elif kind == IocKind.DOMAIN:
            raw = self.exact_domain_fields
        elif kind == IocKind.HASH:
            raw = self.hash_fields
        else:
            raw = ""
        return [line.strip() for line in raw.splitlines() if line.strip()]


class Indicator(models.Model):
    """Current OpenCTI-derived IOC snapshot exported to Wazuh.

    Rows not refreshed by a successful TAXII fetch are deleted by the ingestion
    layer; historical Wazuh matches are stored separately in ``RetroHit``.
    """

    kind = models.CharField(max_length=16, choices=IocKind.choices, db_index=True)
    value = models.CharField(max_length=512, db_index=True)
    source = models.CharField(max_length=64, default="opencti", db_index=True)
    first_seen = models.DateTimeField(default=timezone.now)
    last_seen = models.DateTimeField(default=timezone.now)
    raw_indicator_id = models.CharField(max_length=255, blank=True)

    class Meta:
        unique_together = ("kind", "value")
        indexes = [
            models.Index(fields=["kind", "value"], name="ti_kind_value_idx"),
            models.Index(fields=["source", "last_seen"], name="ti_source_last_seen_idx"),
        ]
        ordering = ["kind", "value"]

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"

    @property
    def cdb_line(self) -> str:
        cfg = TiConfiguration.load()
        return f"{self.value}:{cfg.ioc_tag}"


class FetchRun(models.Model):
    status = models.CharField(max_length=16, choices=RunStatus.choices, default=RunStatus.PENDING, db_index=True)
    triggered_by = models.CharField(max_length=32, default="scheduled")
    celery_task_id = models.CharField(max_length=255, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    total_objects = models.PositiveIntegerField(default=0)
    total_indicators = models.PositiveIntegerField(default=0)
    skipped_indicators = models.PositiveIntegerField(default=0)
    ips = models.PositiveIntegerField(default=0)
    domains = models.PositiveIntegerField(default=0)
    hashes = models.PositiveIntegerField(default=0)
    tranco_excluded_domains = models.PositiveIntegerField(default=0)
    queued_retro_jobs = models.PositiveIntegerField(default=0)
    log = models.TextField(blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        return f"fetch {self.started_at:%Y-%m-%d %H:%M:%S} {self.status}"


class RetroJob(models.Model):
    """Transient work queue for scheduled retro-hunting.

    Successful processing deletes the row; durable matches are stored in ``RetroHit``.
    """
    kind = models.CharField(max_length=16, choices=IocKind.choices, db_index=True)
    value = models.CharField(max_length=512, db_index=True)
    window_start = models.DateTimeField()
    window_end = models.DateTimeField()
    queued_at = models.DateTimeField(default=timezone.now, db_index=True)
    batch_id = models.CharField(max_length=64, blank=True, db_index=True)
    cursor = models.JSONField(null=True, blank=True)
    last_attempt = models.DateTimeField(null=True, blank=True)
    last_error = models.TextField(blank=True)
    attempts = models.PositiveIntegerField(default=0)

    class Meta:
        unique_together = ("kind", "value")
        indexes = [models.Index(fields=["kind", "queued_at"], name="ti_kind_queued_idx"), models.Index(fields=["batch_id"], name="ti_batch_id_idx")]
        ordering = ["-queued_at", "kind", "value"]

    def __str__(self) -> str:
        return f"{self.kind}:{self.value}"


class RetroHuntRun(models.Model):
    status = models.CharField(max_length=16, choices=RunStatus.choices, default=RunStatus.PENDING, db_index=True)
    triggered_by = models.CharField(max_length=32, default="scheduled")
    manual_kind = models.CharField(max_length=16, choices=IocKind.choices, blank=True)
    manual_value = models.CharField(max_length=512, blank=True)
    started_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    batches = models.PositiveIntegerField(default=0)
    iocs_tested = models.PositiveIntegerField(default=0)
    hits = models.PositiveIntegerField(default=0)
    emitted = models.PositiveIntegerField(default=0)
    pending_after = models.PositiveIntegerField(default=0)
    query_json = models.JSONField(null=True, blank=True)
    result_json = models.JSONField(null=True, blank=True)
    error = models.TextField(blank=True)

    class Meta:
        ordering = ["-started_at"]

    def __str__(self) -> str:
        label = self.triggered_by
        if self.manual_kind:
            label = f"manual {self.manual_kind}:{self.manual_value}"
        return f"retrohunt {label} {self.started_at:%Y-%m-%d %H:%M:%S} {self.status}"


class RetroHit(models.Model):
    """Durable Wazuh event matched by a retro-hunt query."""
    kind = models.CharField(max_length=16, choices=IocKind.choices, db_index=True)
    value = models.CharField(max_length=512, db_index=True)
    index_name = models.CharField(max_length=255)
    document_id = models.CharField(max_length=255)
    timestamp = models.CharField(max_length=128, blank=True)
    agent_name = models.CharField(max_length=255, blank=True)
    rule_id = models.CharField(max_length=64, blank=True)
    rule_description = models.TextField(blank=True)
    location = models.CharField(max_length=512, blank=True)
    decoder_name = models.CharField(max_length=255, blank=True)
    matched_fields = models.TextField(blank=True)
    raw_event = models.JSONField(default=dict)
    run = models.ForeignKey(RetroHuntRun, null=True, blank=True, on_delete=models.SET_NULL, related_name="hit_rows")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ("kind", "value", "index_name", "document_id")
        indexes = [models.Index(fields=["kind", "value"], name="ti_hit_kind_value_idx"), models.Index(fields=["created_at"], name="ti_hit_created_idx")]
        ordering = ["-created_at"]

    def __str__(self) -> str:
        return f"{self.kind}:{self.value} {self.index_name}/{self.document_id}"


def sync_periodic_tasks_safe(config: TiConfiguration | None = None) -> None:
    """Create or update django-celery-beat rows when its tables are available."""
    try:
        from django_celery_beat.models import CrontabSchedule, IntervalSchedule, PeriodicTask

        config = config or TiConfiguration.load()

        crontab, _ = CrontabSchedule.objects.get_or_create(
            minute=config.fetch_cron_minute or "0",
            hour=config.fetch_cron_hour or "3,15",
            day_of_week="*",
            day_of_month="*",
            month_of_year="*",
            timezone="Europe/Rome",  # hardcoded; change if your Celery Beat runs elsewhere
        )
        PeriodicTask.objects.update_or_create(
            name="Wazuh-TI fetch OpenCTI TAXII IOCs",
            defaults={
                "task": "threatintel.tasks.fetch_opencti_iocs_task",
                "crontab": crontab,
                "interval": None,
                "enabled": config.fetch_enabled,
            },
        )

        interval, _ = IntervalSchedule.objects.get_or_create(
            every=config.retrohunt_interval_minutes,
            period=IntervalSchedule.MINUTES,
        )
        PeriodicTask.objects.update_or_create(
            name="Wazuh-TI process retro-hunt queue",
            defaults={
                "task": "threatintel.tasks.run_retrohunt_queue_task",
                "interval": interval,
                "crontab": None,
                "enabled": config.retrohunt_enabled,
            },
        )
    except (ImportError, OperationalError, ProgrammingError):
        return
