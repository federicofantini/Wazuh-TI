from __future__ import annotations

import time
from datetime import timedelta
from typing import Any

import requests
import urllib3
from django.db import models, transaction
from django.utils import timezone
from urllib3.exceptions import InsecureRequestWarning

from threatintel.iocs import is_local_domain, is_local_ip, normalize_domain, normalize_hash, normalize_ip
from threatintel.models import IocKind, RetroHit, RetroHuntRun, RetroJob, RunStatus, TiConfiguration

WAZUH_TIME_FIELD = "timestamp"
WAZUH_ID_FIELD = "id"
MAX_ERROR_LENGTH = 2000


def normalize_ioc(kind: str, value: str) -> str:
    # Searching a local value matches nearly every stored alert, so a manual run is
    # refused up front rather than filling RetroHit with noise.
    if kind == IocKind.IP:
        normalized = normalize_ip(value)
        if not normalized:
            raise ValueError(f"Invalid IP address: {value}")
        if is_local_ip(normalized):
            raise ValueError(f"{normalized} is a local or non-routable value and cannot be retro-hunted")
        return normalized

    if kind == IocKind.DOMAIN:
        normalized = normalize_domain(value)
        if not normalized:
            raise ValueError(f"Invalid domain: {value}")
        if is_local_domain(normalized):
            raise ValueError(f"{normalized} is a local or non-routable value and cannot be retro-hunted")
        return normalized

    if kind == IocKind.HASH:
        normalized = normalize_hash(value)
        if not normalized:
            raise ValueError("Hash must be a valid MD5, SHA1, SHA256 or SHA512 digest")
        return normalized

    raise ValueError(f"Unsupported IOC kind: {kind}")


def indexer_verify(config: TiConfiguration) -> bool | str:
    if config.wazuh_indexer_verify_tls:
        return config.wazuh_indexer_ca_bundle or True

    # When TLS verification is disabled for a self-signed Indexer, keep HTTPS but
    # suppress the client-side certificate warning.
    urllib3.disable_warnings(InsecureRequestWarning)
    return False


def nested_value(source: dict[str, Any], path: str) -> Any:
    current: Any = source
    for part in path.split("."):
        if not isinstance(current, dict):
            return None
        current = current.get(part)
    return current


def scalar_values(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        out: list[str] = []
        for item in value:
            out.extend(scalar_values(item))
        return out
    return [str(value)]


def unclaimed_batch_filter() -> models.Q:
    return models.Q(batch_id="") | models.Q(batch_id__isnull=True)


def cursor_filter(cursor: Any) -> models.Q:
    if cursor is None:
        return models.Q(cursor__isnull=True) | models.Q(cursor=None)
    return models.Q(cursor=cursor)


def queued_jobs_count() -> int:
    return RetroJob.objects.count()


def batch_capacity(config: TiConfiguration, kind: str) -> int:
    if kind == IocKind.HASH:
        return max(1, config.retrohunt_hash_iocs_per_batch)
    return max(1, config.retrohunt_iocs_per_batch)


def configured_fields(config: TiConfiguration, kind: str) -> list[str]:
    fields = config.field_list(kind)
    if not fields:
        raise RuntimeError(f"No Wazuh fields configured for IOC kind {kind}")
    return fields


def hash_variants(value: str) -> tuple[str, ...]:
    lower = value.lower()
    upper = value.upper()
    return (lower,) if lower == upper else (lower, upper)


def build_clauses(config: TiConfiguration, kind: str, values: list[str]) -> list[dict[str, Any]]:
    fields = configured_fields(config, kind)

    if kind in {IocKind.IP, IocKind.DOMAIN}:
        # IPs and domains use exact terms queries. Hashes use wildcards because
        # Wazuh often stores multiple digest algorithms in one text field.
        return [{"terms": {field: values}} for field in fields]

    clauses: list[dict[str, Any]] = []
    for field in fields:
        for value in values:
            for candidate in hash_variants(value):
                clauses.append({"wildcard": {field: f"*{candidate}*"}})
    return clauses


def build_query(
    config: TiConfiguration,
    kind: str,
    values: list[str],
    window_start,
    window_end,
    page_size: int,
    cursor=None,
) -> dict[str, Any]:
    source_fields = configured_fields(config, kind)
    clauses = build_clauses(config, kind, values)

    query: dict[str, Any] = {
        "size": page_size,
        "track_total_hits": False,
        # search_after requires a deterministic sort; the event id breaks ties
        # between alerts with the same timestamp.
        "sort": [
            {WAZUH_TIME_FIELD: {"order": "asc"}},
            {WAZUH_ID_FIELD: {"order": "asc", "unmapped_type": "keyword"}},
        ],
        "_source": [
            WAZUH_TIME_FIELD,
            WAZUH_ID_FIELD,
            "agent",
            "rule",
            "location",
            "decoder",
            *source_fields,
        ],
        "query": {
            "bool": {
                "filter": [
                    {
                        "range": {
                            WAZUH_TIME_FIELD: {
                                "gte": window_start.isoformat(timespec="seconds"),
                                "lte": window_end.isoformat(timespec="seconds"),
                            }
                        }
                    },
                    {"bool": {"should": clauses, "minimum_should_match": 1}},
                ]
            }
        },
    }

    if cursor:
        query["search_after"] = cursor

    return query


def matched_fields_and_values(
    config: TiConfiguration,
    kind: str,
    candidates: set[str],
    source: dict[str, Any],
) -> dict[str, list[str]]:
    matches: dict[str, list[str]] = {}

    # Re-check the returned _source locally before storing evidence. The Indexer
    # query finds candidate events; this step confirms the exact IOC match.
    for field in configured_fields(config, kind):
        for raw in scalar_values(nested_value(source, field)):
            if kind == IocKind.IP:
                value = normalize_ip(raw)
                if value in candidates:
                    matches.setdefault(value, []).append(field)

            elif kind == IocKind.DOMAIN:
                value = normalize_domain(raw)
                if value in candidates:
                    matches.setdefault(value, []).append(field)

            else:
                raw_lower = raw.lower()
                for candidate in candidates:
                    if candidate.lower() in raw_lower:
                        matches.setdefault(candidate, []).append(field)

    return matches


def search_indexer(config: TiConfiguration, query: dict[str, Any]) -> list[dict[str, Any]]:
    if not config.wazuh_indexer_username or not config.wazuh_indexer_password:
        raise RuntimeError("Wazuh Indexer credentials are not configured")

    response = requests.post(
        f"{config.wazuh_indexer_url.rstrip('/')}/{config.retrohunt_index}/_search",
        auth=(config.wazuh_indexer_username, config.wazuh_indexer_password),
        json=query,
        timeout=config.request_timeout_seconds,
        verify=indexer_verify(config),
    )

    try:
        response.raise_for_status()
    except requests.HTTPError as exc:
        raise RuntimeError(f"Wazuh Indexer query failed: {response.status_code} {response.text[:500]}") from exc

    hits = response.json().get("hits", {}).get("hits", [])
    if not isinstance(hits, list):
        raise RuntimeError("Unexpected Wazuh Indexer response: hits.hits is not a list")
    return hits


def select_next_batch(config: TiConfiguration, handled_batch_ids: set[str]) -> list[RetroJob]:
    candidates = RetroJob.objects.all()
    if handled_batch_ids:
        candidates = candidates.exclude(batch_id__in=handled_batch_ids)

    # Empty last_error sorts before any non-empty string, so error-free jobs
    # are processed before ones that have already failed at least once.
    anchor = candidates.order_by("last_error", "-queued_at", "kind", "value").first()
    if not anchor:
        return []

    if anchor.batch_id:
        return list(RetroJob.objects.filter(batch_id=anchor.batch_id).order_by("value"))

    batch_id = timezone.now().strftime("%Y%m%d%H%M%S%f")
    max_iocs = batch_capacity(config, anchor.kind)

    with transaction.atomic():
        # Claim queue rows with row-level locks so concurrent Celery workers do not
        # search or delete the same IOC batch.
        rows = list(
            RetroJob.objects.select_for_update(skip_locked=True)
            .filter(
                unclaimed_batch_filter(),
                cursor_filter(anchor.cursor),
                kind=anchor.kind,
                window_start=anchor.window_start,
                window_end=anchor.window_end,
                queued_at=anchor.queued_at,
            )
            .order_by("value")[:max_iocs]
        )

        if not rows:
            return []

        RetroJob.objects.filter(pk__in=[row.pk for row in rows]).update(batch_id=batch_id)

    return list(RetroJob.objects.filter(batch_id=batch_id).order_by("value"))


def event_timestamp(source: dict[str, Any]) -> str:
    return str(source.get(WAZUH_TIME_FIELD, ""))


def persist_hits(
    config: TiConfiguration,
    run: RetroHuntRun,
    kind: str,
    candidates: set[str],
    hits: list[dict[str, Any]],
    max_events: int,
) -> tuple[int, bool]:
    emitted = 0
    overflow = False

    for hit in hits:
        if emitted >= max_events:
            overflow = True
            break

        index_name = str(hit.get("_index", ""))
        document_id = str(hit.get("_id", ""))
        source = hit.get("_source", {})

        if not index_name or not document_id or not isinstance(source, dict):
            continue

        matches = matched_fields_and_values(config, kind, candidates, source)
        if not matches:
            continue

        agent = source.get("agent") if isinstance(source.get("agent"), dict) else {}
        rule = source.get("rule") if isinstance(source.get("rule"), dict) else {}
        decoder = source.get("decoder") if isinstance(source.get("decoder"), dict) else {}

        for value, fields in matches.items():
            if emitted >= max_events:
                overflow = True
                break

            obj, created = RetroHit.objects.get_or_create(
                kind=kind,
                value=value,
                index_name=index_name,
                document_id=document_id,
                defaults={
                    "timestamp": event_timestamp(source),
                    "agent_name": str(agent.get("name", "")),
                    "rule_id": str(rule.get("id", "")),
                    "rule_description": str(rule.get("description", "")),
                    "location": str(source.get("location", "")),
                    "decoder_name": str(decoder.get("name", "")),
                    "matched_fields": ",".join(sorted(set(fields))),
                    "raw_event": hit,
                    "run": run,
                },
            )

            if created:
                emitted += 1
            elif obj.run_id is None:
                # Hit already exists but is orphaned: its original RetroHuntRun was
                # deleted (SET_NULL). Re-link it to the current run so the admin shows
                # it as part of a known run rather than floating unattached.
                obj.run = run
                obj.save(update_fields=["run"])

    return emitted, not overflow


def finish_run(
    run: RetroHuntRun,
    status: str,
    error: str = "",
    batches: int = 0,
    iocs_tested: int = 0,
    hits: int = 0,
    emitted: int = 0,
) -> RetroHuntRun:
    run.status = status
    run.error = error
    run.finished_at = timezone.now()
    run.batches = batches
    run.iocs_tested = iocs_tested
    run.hits = hits
    run.emitted = emitted
    run.pending_after = queued_jobs_count()
    run.save()
    return run


def mark_batch_attempt(batch_id: str, attempt_time, error: str = "", cursor: list[Any] | None = None) -> None:
    updates: dict[str, Any] = {
        "last_attempt": attempt_time,
        "last_error": error[:MAX_ERROR_LENGTH],
        "attempts": models.F("attempts") + 1,
    }
    if cursor is not None:
        updates["cursor"] = cursor
    RetroJob.objects.filter(batch_id=batch_id).update(**updates)


def delete_completed_batch(batch_id: str) -> None:
    RetroJob.objects.filter(batch_id=batch_id).delete()


def run_queue(triggered_by: str = "scheduled") -> RetroHuntRun:
    config = TiConfiguration.load()
    run = RetroHuntRun.objects.create(status=RunStatus.RUNNING, triggered_by=triggered_by)

    if not config.retrohunt_enabled:
        return finish_run(run, RunStatus.SKIPPED, error="Retro-hunt is disabled")

    if config.retrohunt_batches_per_run <= 0:
        return finish_run(run, RunStatus.SKIPPED, error="retrohunt_batches_per_run must be greater than 0")

    if config.retrohunt_page_size <= 0:
        return finish_run(run, RunStatus.SKIPPED, error="retrohunt_page_size must be greater than 0")

    if config.retrohunt_max_alerts_per_run <= 0:
        return finish_run(run, RunStatus.SKIPPED, error="retrohunt_max_alerts_per_run must be greater than 0")

    handled_batch_ids: set[str] = set()
    alerts_left = config.retrohunt_max_alerts_per_run
    processed_batches = 0
    processed_iocs = 0
    hits_total = 0
    emitted_total = 0
    errors = 0

    try:
        for position in range(config.retrohunt_batches_per_run):
            if alerts_left <= 0:
                break

            batch = select_next_batch(config, handled_batch_ids)
            if not batch:
                break

            batch_id = batch[0].batch_id
            handled_batch_ids.add(batch_id)

            kind = batch[0].kind
            values = [row.value for row in batch]
            # Cap page_size to the remaining budget so we never fetch more results
            # from the Indexer than we can emit in this run.
            page_size = min(config.retrohunt_page_size, alerts_left)
            query = build_query(config, kind, values, batch[0].window_start, batch[0].window_end, page_size, batch[0].cursor)
            attempt_time = timezone.now()

            try:
                hits = search_indexer(config, query)
                emitted, page_complete = persist_hits(config, run, kind, set(values), hits, alerts_left)

                hits_total += len(hits)
                emitted_total += emitted
                alerts_left -= emitted
                processed_batches += 1
                processed_iocs += len(batch)

                # Three outcomes after processing a page:
                #
                # 1. Budget exhausted mid-page (not page_complete): leave the batch
                #    cursor unchanged. The next run re-queries from the same position
                #    with a fresh budget; get_or_create makes re-processing idempotent.
                #
                # 2. Partial page (len(hits) < page_size): no more results exist for
                #    this batch — delete the queue rows so the IOCs are not re-searched.
                #
                # 3. Full page (len(hits) == page_size): more results may follow.
                #    Save the search_after cursor from the last hit so the next run
                #    continues pagination from where this one stopped.
                if not page_complete:
                    mark_batch_attempt(batch_id, attempt_time)
                elif len(hits) < page_size:
                    delete_completed_batch(batch_id)
                else:
                    cursor = hits[-1].get("sort")
                    if not isinstance(cursor, list):
                        raise RuntimeError("Missing search_after cursor on full result page")
                    mark_batch_attempt(batch_id, attempt_time, cursor=cursor)

            except Exception as exc:
                errors += 1
                mark_batch_attempt(batch_id, attempt_time, error=str(exc))

            if config.retrohunt_query_delay_seconds > 0 and position < config.retrohunt_batches_per_run - 1 and alerts_left > 0:
                time.sleep(config.retrohunt_query_delay_seconds)

        status = RunStatus.SUCCESS if errors == 0 else RunStatus.FAILED
        error = f"{errors} batch error(s)" if errors else ""
        return finish_run(
            run,
            status,
            error=error,
            batches=processed_batches,
            iocs_tested=processed_iocs,
            hits=hits_total,
            emitted=emitted_total,
        )

    except Exception as exc:
        finish_run(
            run,
            RunStatus.FAILED,
            error=str(exc),
            batches=processed_batches,
            iocs_tested=processed_iocs,
            hits=hits_total,
            emitted=emitted_total,
        )
        raise


def run_manual(kind: str, value: str, days: int, size: int) -> RetroHuntRun:
    config = TiConfiguration.load()
    normalized = normalize_ioc(kind, value)
    run = RetroHuntRun.objects.create(
        status=RunStatus.RUNNING,
        triggered_by="manual",
        manual_kind=kind,
        manual_value=normalized,
    )

    try:
        end = timezone.now()
        start = end - timedelta(days=days)
        query = build_query(config, kind, [normalized], start, end, size)
        hits = search_indexer(config, query)
        emitted, _complete = persist_hits(config, run, kind, {normalized}, hits, size)

        run.status = RunStatus.SUCCESS
        run.finished_at = timezone.now()
        run.iocs_tested = 1
        run.hits = len(hits)
        run.emitted = emitted
        run.query_json = query
        # Store only a small response sample in the run audit row; full evidence
        # is stored in RetroHit and exported through the NDJSON endpoint.
        run.result_json = {"hits": hits[: min(len(hits), 50)]}
        run.pending_after = queued_jobs_count()
        run.save()
        return run

    except Exception as exc:
        run.status = RunStatus.FAILED
        run.finished_at = timezone.now()
        run.error = str(exc)
        run.pending_after = queued_jobs_count()
        run.save()
        raise