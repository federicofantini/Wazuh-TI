from __future__ import annotations

from django import forms
from django.contrib import admin, messages
from django.http import HttpRequest
from django.shortcuts import redirect
from django.template.response import TemplateResponse
from django.urls import path, reverse
from django.utils.html import format_html

from threatintel.models import FetchRun, Indicator, IocKind, RetroHit, RetroHuntRun, RetroJob, TiConfiguration
from threatintel.retrohunt import run_manual
from threatintel.tasks import fetch_opencti_iocs_task, run_retrohunt_queue_task


class ManualRetroHuntForm(forms.Form):
    kind = forms.ChoiceField(choices=IocKind.choices)
    value = forms.CharField(max_length=512)
    days = forms.IntegerField(min_value=1, max_value=3650, initial=90)
    size = forms.IntegerField(min_value=1, max_value=500, initial=100)


@admin.register(TiConfiguration)
class TiConfigurationAdmin(admin.ModelAdmin):
    readonly_fields = ("admin_actions",)
    fieldsets = (
        (
            "Actions",
            {
                "description": (
                    "Manual administrative shortcuts for triggering the main ingestion and "
                    "retro-hunting workflows without leaving the configuration page."
                ),
                "fields": ("admin_actions",),
            },
        ),
        (
            "Export API",
            {
                "description": (
                    "Settings for the HTTP endpoints consumed by the Wazuh manager. "
                    "The API token protects the exported IOC lists."
                ),
                "fields": ("export_api_token", "ioc_tag"),
            },
        ),
        (
            "OpenCTI TAXII fetch",
            {
                "description": (
                    "OpenCTI TAXII collection settings. The scheduled fetch imports a "
                    "fresh IOC snapshot, queues retro-hunt jobs for new values, and "
                    "deletes OpenCTI indicators that disappeared from the latest snapshot."
                ),
                "fields": (
                    "taxii_url",
                    "request_timeout_seconds",
                    "fetch_enabled",
                    "fetch_cron_minute",
                    "fetch_cron_hour",
                ),
            },
        ),
        (
            "Tranco cache",
            {
                "description": (
                    "Local Tranco cache used to suppress highly popular domains before they "
                    "are exported to Wazuh or queued for retro-hunting."
                ),
                "fields": (
                    "tranco_enabled",
                    "tranco_dir",
                    "tranco_max_age_days",
                    "tranco_download_retries",
                    "tranco_retry_sleep_seconds",
                ),
            },
        ),
        (
            "Retro-hunting schedule",
            {
                "description": (
                    "Controls when and how far back the scheduled retro-hunt searches Wazuh "
                    "historical alerts for newly imported OpenCTI indicators."
                ),
                "fields": (
                    "retrohunt_enabled",
                    "retrohunt_queue_existing_on_first_run",
                    "retrohunt_interval_minutes",
                    "retrohunt_index",
                    "retrohunt_lookback_days",
                ),
            },
        ),
        (
            "Retro-hunting limits",
            {
                "description": (
                    "Execution limits used to keep each retro-hunt run bounded. These values "
                    "control batch size, pagination, maximum emitted alerts, and the delay "
                    "between Wazuh Indexer queries."
                ),
                "fields": (
                    "retrohunt_batches_per_run",
                    "retrohunt_iocs_per_batch",
                    "retrohunt_hash_iocs_per_batch",
                    "retrohunt_page_size",
                    "retrohunt_max_alerts_per_run",
                    "retrohunt_query_delay_seconds",
                    "retrohunt_hash_search_enabled",
                ),
            },
        ),
        (
            "Wazuh Indexer",
            {
                "description": (
                    "Connection settings for the Wazuh Indexer or OpenSearch backend queried "
                    "during retro-hunting."
                ),
                "fields": (
                    "wazuh_indexer_url",
                    "wazuh_indexer_username",
                    "wazuh_indexer_password",
                    "wazuh_indexer_verify_tls",
                    "wazuh_indexer_ca_bundle",
                ),
            },
        ),
        (
            "Retro-hunt search fields",
            {
                "description": (
                    "Wazuh alert field paths queried during retro-hunting. Use dotted field "
                    "paths, one per line, for exact IP matches, exact domain matches, and "
                    "hash searches."
                ),
                "fields": (
                    "exact_ip_fields",
                    "exact_domain_fields",
                    "hash_fields",
                ),
            },
        ),
    )

    def has_add_permission(self, request: HttpRequest) -> bool:
        return not TiConfiguration.objects.exists()

    def has_delete_permission(self, request: HttpRequest, obj=None) -> bool:
        return False

    def get_urls(self):
        # Long-running TAXII and Wazuh jobs are enqueued through Celery so the
        # admin request thread remains responsive.
        return [
            path("manual-retrohunt/", self.admin_site.admin_view(self.manual_retrohunt_view), name="threatintel_manual_retrohunt"),
            path("trigger-fetch/", self.admin_site.admin_view(self.trigger_fetch_view), name="threatintel_trigger_fetch"),
            path("trigger-retrohunt/", self.admin_site.admin_view(self.trigger_retrohunt_view), name="threatintel_trigger_retrohunt"),
        ] + super().get_urls()

    def changelist_view(self, request: HttpRequest, extra_context=None):
        config = TiConfiguration.load()
        return redirect("admin:threatintel_ticonfiguration_change", object_id=config.pk)

    @admin.display(description="Admin actions")
    def admin_actions(self, obj: TiConfiguration):
        return format_html(
            '<div class="wazuh-ti-action-bar">'
            '<a class="button wazuh-ti-action-button" href="{}">Manual retro-hunt</a>'
            '<a class="button wazuh-ti-action-button" href="{}">Queue TAXII fetch</a>'
            '<a class="button wazuh-ti-action-button" href="{}">Process retro queue</a>'
            '</div>',
            reverse("admin:threatintel_manual_retrohunt"),
            reverse("admin:threatintel_trigger_fetch"),
            reverse("admin:threatintel_trigger_retrohunt"),
        )

    def manual_retrohunt_view(self, request: HttpRequest):
        result = None
        if request.method == "POST":
            form = ManualRetroHuntForm(request.POST)
            if form.is_valid():
                try:
                    result = run_manual(
                        kind=form.cleaned_data["kind"],
                        value=form.cleaned_data["value"],
                        days=form.cleaned_data["days"],
                        size=form.cleaned_data["size"],
                    )
                    messages.success(
                        request,
                        f"Manual retro-hunt completed: {result.hits} hit(s), {result.emitted} new stored hit(s).",
                    )
                except Exception as exc:
                    messages.error(request, f"Manual retro-hunt failed: {exc}")
        else:
            form = ManualRetroHuntForm()

        context = {
            **self.admin_site.each_context(request),
            "title": "Manual retro-hunt",
            "form": form,
            "result": result,
            "recent_runs": RetroHuntRun.objects.filter(triggered_by="manual")[:10],
        }
        return TemplateResponse(request, "admin/threatintel/manual_retrohunt.html", context)

    def trigger_fetch_view(self, request: HttpRequest):
        task = fetch_opencti_iocs_task.delay(triggered_by="manual")
        messages.success(request, f"OpenCTI TAXII fetch queued in Celery: {task.id}")
        return redirect("admin:threatintel_ticonfiguration_change", object_id=1)

    def trigger_retrohunt_view(self, request: HttpRequest):
        task = run_retrohunt_queue_task.delay(triggered_by="manual")
        messages.success(request, f"Retro-hunt queue processing queued in Celery: {task.id}")
        return redirect("admin:threatintel_ticonfiguration_change", object_id=1)


@admin.register(Indicator)
class IndicatorAdmin(admin.ModelAdmin):
    list_display = ("kind", "value", "source", "first_seen", "last_seen", "cdb_preview")
    list_filter = ("kind", "source")
    search_fields = ("value",)
    readonly_fields = ("first_seen", "last_seen", "cdb_preview")
    ordering = ("kind", "value")
    actions = None

    fieldsets = (
        (
            "Current exported IOC",
            {
                "description": (
                    "This table is the current OpenCTI export snapshot. It is not a "
                    "long-term IOC archive: after a successful TAXII fetch, indicators "
                    "that are no longer present in the latest OpenCTI snapshot are deleted. "
                    "IOC rows therefore have no separate lifecycle status."
                ),
                "fields": ("kind", "value", "source", "cdb_preview", "first_seen", "last_seen"),
            },
        ),
    )

    def has_add_permission(self, request):
        return False

    @admin.display(description="CDB line")
    def cdb_preview(self, obj: Indicator):
        return obj.cdb_line


@admin.register(FetchRun)
class FetchRunAdmin(admin.ModelAdmin):
    list_display = ("started_at", "status_badge", "triggered_by", "total_indicators", "ips", "domains", "hashes", "tranco_excluded_domains", "queued_retro_jobs")
    list_filter = ("status", "triggered_by", "started_at")
    search_fields = ("log", "error", "celery_task_id")
    readonly_fields = [field.name for field in FetchRun._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="status")
    def status_badge(self, obj: FetchRun):
        color = {"success": "#28a745", "failed": "#dc3545", "running": "#17a2b8", "skipped": "#6c757d"}.get(obj.status, "#ffc107")
        return format_html('<strong style="color:{}">{}</strong>', color, obj.status)


@admin.register(RetroJob)
class RetroJobAdmin(admin.ModelAdmin):
    list_display = (
        "queue_state",
        "queued_at",
        "kind",
        "short_value",
        "attempts",
        "last_attempt",
        "batch_short",
        "cursor_state",
        "short_error",
    )
    list_filter = ("kind", "queued_at", "last_attempt", "attempts")
    search_fields = ("value", "last_error", "batch_id")
    readonly_fields = [field.name for field in RetroJob._meta.fields]
    fieldsets = (
        (
            "How to use this page",
            {
                "description": (
                    "This table is the internal retro-hunt processing queue. Each row is one IOC "
                    "waiting to be searched in historical Wazuh alerts. Rows are created by the "
                    "OpenCTI TAXII fetch and are deleted immediately after the Wazuh query "
                    "has been fully processed. "
                    "Use this page for troubleshooting queue backlog, retries, stuck batches, "
                    "pagination state, and Wazuh Indexer errors. Do not add or edit jobs manually."
                ),
                "fields": (),
            },
        ),
        (
            "IOC and search window",
            {
                "description": (
                    "The IOC value and the historical time range that will be queried in the "
                    "Wazuh Indexer."
                ),
                "fields": ("kind", "value", "window_start", "window_end", "queued_at"),
            },
        ),
        (
            "Processing state",
            {
                "description": (
                    "batch_id groups multiple IOC jobs into one Indexer query. cursor stores the "
                    "OpenSearch search_after value when a batch has more result pages to process. "
                    "attempts and last_attempt show retry activity."
                ),
                "fields": ("batch_id", "cursor", "attempts", "last_attempt"),
            },
        ),
        (
            "Last error",
            {
                "description": (
                    "If the Indexer query fails, the error is stored here and the job remains in "
                    "the queue for a later retry."
                ),
                "fields": ("last_error",),
            },
        ),
    )

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="State")
    def queue_state(self, obj: RetroJob):
        if obj.last_error:
            return format_html('<strong style="color:#dc3545">retry/error</strong>')
        if obj.batch_id and obj.cursor:
            return format_html('<strong style="color:#17a2b8">paged</strong>')
        if obj.batch_id:
            return format_html('<strong style="color:#ffc107">claimed</strong>')
        return format_html('<strong style="color:#28a745">pending</strong>')

    @admin.display(description="IOC")
    def short_value(self, obj: RetroJob):
        return (obj.value[:80] + "...") if len(obj.value) > 80 else obj.value

    @admin.display(description="batch")
    def batch_short(self, obj: RetroJob):
        if not obj.batch_id:
            return "-"
        return obj.batch_id[-8:]

    @admin.display(description="cursor")
    def cursor_state(self, obj: RetroJob):
        return "search_after" if obj.cursor else "-"

    @admin.display(description="last error")
    def short_error(self, obj: RetroJob):
        return (obj.last_error[:120] + "...") if len(obj.last_error) > 120 else obj.last_error


@admin.register(RetroHuntRun)
class RetroHuntRunAdmin(admin.ModelAdmin):
    list_display = ("started_at", "status_badge", "triggered_by", "manual_kind", "manual_value", "batches", "iocs_tested", "hits", "pending_after")
    list_filter = ("status", "triggered_by", "manual_kind", "started_at")
    search_fields = ("manual_value", "error")
    readonly_fields = [field.name for field in RetroHuntRun._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="status")
    def status_badge(self, obj: RetroHuntRun):
        color = {"success": "#28a745", "failed": "#dc3545", "running": "#17a2b8", "skipped": "#6c757d"}.get(obj.status, "#ffc107")
        return format_html('<strong style="color:{}">{}</strong>', color, obj.status)


@admin.register(RetroHit)
class RetroHitAdmin(admin.ModelAdmin):
    list_display = ("created_at", "kind", "value", "timestamp", "agent_name", "rule_id", "short_rule", "location")
    list_filter = ("kind", "agent_name", "rule_id", "created_at")
    search_fields = ("value", "agent_name", "rule_id", "rule_description", "location", "index_name", "document_id")
    readonly_fields = [field.name for field in RetroHit._meta.fields]

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    @admin.display(description="rule")
    def short_rule(self, obj: RetroHit):
        return (obj.rule_description[:120] + "...") if len(obj.rule_description) > 120 else obj.rule_description
