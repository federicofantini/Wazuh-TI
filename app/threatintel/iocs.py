"""OpenCTI IOC ingestion and snapshot maintenance.

The ingestion pipeline downloads the current TAXII collection, extracts Wazuh-ready
IOC values, filters popular domains through Tranco, queues retro-hunt work for new
values, and keeps ``Indicator`` bounded to the latest OpenCTI snapshot.
"""

from __future__ import annotations

import csv
import ipaddress
import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator
from urllib.parse import urlparse

import requests
from django.db import transaction
from django.utils import timezone

from threatintel.models import FetchRun, Indicator, IocKind, RetroJob, RunStatus, TiConfiguration

TRANCO_BASE_URL = "https://tranco-list.eu"
TRANCO_LATEST_LIST_URL = f"{TRANCO_BASE_URL}/latest_list"
TRANCO_CHUNK_SIZE_BYTES = 1024 * 1024
TRANCO_CONNECT_TIMEOUT_SECONDS = 15
TRANCO_READ_TIMEOUT_SECONDS = 300
TRANCO_LIST_ID_RE = re.compile(r"/list/([A-Za-z0-9]+)(?:$|[?#])")
TRANCO_DOWNLOAD_HREF_RE = re.compile(r"href=[\"\']/download/([A-Za-z0-9]+)/full[\"\']")
TRANCO_PAGE_ID_RE = re.compile(r"Tranco list with ID\s*<[^>]*>\s*([A-Za-z0-9]+)", re.IGNORECASE)
QUOTED_VALUE_RE = re.compile(r"'([^']+)'")
HASH_PATTERN_RE = re.compile(r"file:hashes(?:\.'?[A-Za-z0-9_-]+'?)?\s*=\s*'([^']+)'", re.IGNORECASE)
IP_PATTERN_RE = re.compile(r"(?:ipv4-addr|ipv6-addr):value\s*=\s*'([^']+)'", re.IGNORECASE)
DOMAIN_PATTERN_RE = re.compile(r"(?:domain-name|hostname):value\s*=\s*'([^']+)'", re.IGNORECASE)
URL_PATTERN_RE = re.compile(r"url:value\s*=\s*'([^']+)'", re.IGNORECASE)
TAXII_HEADERS = {"Accept": "application/taxii+json, application/json"}
DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)
HEX_RE = re.compile(r"^[a-fA-F0-9]+$")
OPENCTI_SOURCE = "opencti"
# Special-use TLDs (RFC 6761/6762, ICANN .internal) plus the labels commonly
# squatted on private networks. Matched on the last label, so subdomains follow.
LOCAL_DOMAIN_TLDS = {
    "arpa",
    "corp",
    "example",
    "home",
    "internal",
    "intranet",
    "invalid",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "private",
    "test",
}


class DomainSuffixMatcher:
    """Suffix matcher used to filter domains covered by the Tranco cache.

    A listed parent domain also suppresses its subdomains, reducing noisy matches
    before values are exported to Wazuh or queued for retro-hunting.
    """
    def __init__(self, suffixes: set[str] | None = None) -> None:
        self._suffixes = suffixes or set()

    def __len__(self) -> int:
        return len(self._suffixes)

    def matches(self, domain: str) -> bool:
        normalized = normalize_domain(domain)
        if not normalized:
            return False
        labels = normalized.split(".")
        return any(".".join(labels[offset:]) in self._suffixes for offset in range(len(labels)))


@dataclass
class IocStore:
    """De-duplicated IOC snapshot built in memory during one TAXII fetch."""
    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)
    local_excluded: int = 0

    def add_ip(self, value: Any) -> bool:
        ip_value = normalize_ip(value)
        if not ip_value:
            return False
        if is_local_ip(ip_value):
            self.local_excluded += 1
            return False
        self.ips.add(ip_value)
        return True

    def add_domain(self, value: Any) -> bool:
        domain = normalize_domain(value)
        if not domain:
            return False
        if is_local_domain(domain):
            self.local_excluded += 1
            return False
        self.domains.add(domain)
        return True

    def add_hash(self, value: Any) -> bool:
        digest = normalize_hash(value)
        if not digest:
            return False
        self.hashes.add(digest.lower())
        return True

    def add_host(self, value: Any) -> str | None:
        if self.add_ip(value):
            return IocKind.IP
        if self.add_domain(value):
            return IocKind.DOMAIN
        return None

    def total_count(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.hashes)

    def keys(self) -> set[tuple[str, str]]:
        values: set[tuple[str, str]] = set()
        values.update((IocKind.IP, value) for value in self.ips)
        values.update((IocKind.DOMAIN, value) for value in self.domains)
        values.update((IocKind.HASH, value) for value in self.hashes)
        return values


def clean_string(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def normalize_type(value: Any) -> str:
    value = clean_string(value)
    return value.lower().replace("_", "-").replace(" ", "-") if value else ""


def normalize_ip(value: Any) -> str | None:
    value = clean_string(value)
    if not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_domain(value: Any) -> str | None:
    value = clean_string(value)
    if not value:
        return None
    domain = value.lower().rstrip(".")
    if normalize_ip(domain):
        return None
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    return domain if DOMAIN_RE.match(domain) else None


def is_local_ip(value: str) -> bool:
    """True for addresses that can only describe local or otherwise non-routable hosts.

    Feeds occasionally publish indicators such as 127.0.0.1 or ``*.lan``: they match almost
    every Wazuh alert, so they are dropped instead of flooding retro-hunting. Takes the
    output of ``normalize_ip``, so an unparsable value is a caller bug and raises.
    """
    ip = ipaddress.ip_address(value)
    # IPv4 multicast is not covered by is_global.
    return not ip.is_global or ip.is_multicast


def is_local_domain(value: str) -> bool:
    """Same rationale as ``is_local_ip``, on the output of ``normalize_domain``."""
    return value.rsplit(".", 1)[-1] in LOCAL_DOMAIN_TLDS


def normalize_hash(value: Any) -> str | None:
    value = clean_string(value)
    if not value:
        return None
    digest = value.lower()
    if len(digest) not in {32, 40, 64, 128}:
        return None
    return digest if HEX_RE.match(digest) else None


def extract_host_from_url(value: Any) -> str | None:
    value = clean_string(value)
    if not value:
        return None
    parsed = urlparse(value)
    if not parsed.hostname and "://" not in value:
        parsed = urlparse(f"http://{value}")
    if not parsed.hostname:
        return None
    return parsed.hostname.strip().lower().rstrip(".") or None


def iter_observable_values(indicator: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield normalized observables embedded by OpenCTI before parsing patterns."""
    values = indicator.get("observable_values")
    if isinstance(values, list):
        for value in values:
            if isinstance(value, dict):
                yield value
    extensions = indicator.get("extensions")
    if not isinstance(extensions, dict):
        return
    for extension in extensions.values():
        if not isinstance(extension, dict):
            continue
        values = extension.get("observable_values")
        if isinstance(values, list):
            for value in values:
                if isinstance(value, dict):
                    yield value


def extract_from_observable(observable: dict[str, Any], iocs: IocStore) -> int:
    observable_type = normalize_type(observable.get("type"))
    value = observable.get("value")
    if observable_type in {"ipv4-addr", "ipv6-addr"}:
        return int(iocs.add_ip(value))
    if observable_type in {"domain-name", "hostname"}:
        return int(iocs.add_host(value) is not None)
    if observable_type in {"url", "uri"}:
        return int(iocs.add_host(extract_host_from_url(value)) is not None)
    if observable_type in {"stixfile", "file"}:
        hashes = observable.get("hashes")
        if not isinstance(hashes, dict):
            return 0
        return sum(1 for hash_value in hashes.values() if iocs.add_hash(hash_value))
    return 0


def extract_from_pattern(pattern: Any, iocs: IocStore) -> int:
    """Extract supported IOC values from a STIX pattern string.

    This is intentionally not a full STIX parser. The code only accepts observable
    types that can be exported to Wazuh or queried during retro-hunting.
    """
    pattern = clean_string(pattern)
    if not pattern:
        return 0

    accepted = 0

    for value in IP_PATTERN_RE.findall(pattern):
        accepted += int(iocs.add_ip(value))

    for value in DOMAIN_PATTERN_RE.findall(pattern):
        accepted += int(iocs.add_host(value) is not None)

    for value in URL_PATTERN_RE.findall(pattern):
        accepted += int(iocs.add_host(extract_host_from_url(value)) is not None)

    for value in HASH_PATTERN_RE.findall(pattern):
        accepted += int(iocs.add_hash(value))

    if accepted:
        return accepted

    # Fallback for malformed but still useful patterns coming from external feeds.
    value_match = QUOTED_VALUE_RE.search(pattern)
    if not value_match:
        return 0

    value = value_match.group(1)
    lower_pattern = pattern.lower()
    if "ipv4-addr" in lower_pattern or "ipv6-addr" in lower_pattern:
        return int(iocs.add_ip(value))
    if "domain-name" in lower_pattern or "hostname" in lower_pattern:
        return int(iocs.add_host(value) is not None)
    if "url" in lower_pattern:
        return int(iocs.add_host(extract_host_from_url(value)) is not None)
    if "hashes" in lower_pattern:
        return int(iocs.add_hash(value))
    return 0


def extract_from_indicator(indicator: dict[str, Any], iocs: IocStore) -> int:
    accepted = 0
    for observable in iter_observable_values(indicator):
        accepted += extract_from_observable(observable, iocs)
    if accepted == 0:
        accepted += extract_from_pattern(indicator.get("pattern"), iocs)
    return accepted


def tranco_csv_path(config: TiConfiguration) -> str:
    return os.path.join(config.tranco_dir, "tranco_latest_full.csv")


def tranco_id_path(config: TiConfiguration) -> str:
    return os.path.join(config.tranco_dir, "tranco_latest_id.txt")


def file_is_older_than(path: str, max_age_seconds: int) -> bool:
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return True
    return (time.time() - mtime) > max_age_seconds


def extract_tranco_list_id(page_url: str, html: str) -> str | None:
    for regex in (TRANCO_LIST_ID_RE, TRANCO_DOWNLOAD_HREF_RE, TRANCO_PAGE_ID_RE):
        match = regex.search(page_url if regex is TRANCO_LIST_ID_RE else html)
        if match:
            return match.group(1)
    return None


def resolve_latest_tranco_list_id(config: TiConfiguration) -> str:
    response = requests.get(
        TRANCO_LATEST_LIST_URL,
        timeout=(TRANCO_CONNECT_TIMEOUT_SECONDS, TRANCO_READ_TIMEOUT_SECONDS),
        allow_redirects=True,
    )
    response.raise_for_status()
    list_id = extract_tranco_list_id(response.url, response.text)
    if not list_id:
        raise RuntimeError(f"Could not extract Tranco list ID from {response.url!r}")
    return list_id


def write_tranco_id(config: TiConfiguration, list_id: str) -> None:
    os.makedirs(config.tranco_dir, exist_ok=True)
    path = tranco_id_path(config)
    tmp_path = f"{path}.tmp"
    with open(tmp_path, "w", encoding="utf-8") as output:
        output.write(f"{list_id}\n")
    os.replace(tmp_path, path)


def download_tranco_csv(config: TiConfiguration, log: list[str]) -> str:
    """Download the latest Tranco list using a temporary file and atomic replace."""
    os.makedirs(config.tranco_dir, exist_ok=True)
    path = tranco_csv_path(config)
    tmp_path = f"{path}.tmp"
    last_error: Exception | None = None
    for attempt in range(1, config.tranco_download_retries + 1):
        try:
            list_id = resolve_latest_tranco_list_id(config)
            download_url = f"{TRANCO_BASE_URL}/download/{list_id}/full"
            log.append(f"[TRANCO] downloading list_id={list_id} attempt={attempt}")
            with requests.get(
                download_url,
                timeout=(TRANCO_CONNECT_TIMEOUT_SECONDS, TRANCO_READ_TIMEOUT_SECONDS),
                stream=True,
                allow_redirects=True,
            ) as response:
                response.raise_for_status()
                with open(tmp_path, "wb") as output:
                    for chunk in response.iter_content(chunk_size=TRANCO_CHUNK_SIZE_BYTES):
                        if chunk:
                            output.write(chunk)
            os.replace(tmp_path, path)
            write_tranco_id(config, list_id)
            return list_id
        except (requests.RequestException, RuntimeError) as exc:
            last_error = exc
            try:
                os.unlink(tmp_path)
            except FileNotFoundError:
                pass
            if attempt < config.tranco_download_retries:
                time.sleep(config.tranco_retry_sleep_seconds)
    raise RuntimeError(f"Tranco download failed: {last_error}")


def ensure_tranco_csv(config: TiConfiguration, log: list[str]) -> bool:
    if not config.tranco_enabled:
        log.append("[TRANCO] disabled")
        return False
    path = tranco_csv_path(config)
    if not file_is_older_than(path, config.tranco_max_age_days * 24 * 60 * 60):
        log.append(f"[TRANCO] using cached CSV {path}")
        return True
    try:
        list_id = download_tranco_csv(config, log)
        log.append(f"[TRANCO] refreshed list_id={list_id}")
        return True
    except Exception as exc:
        if os.path.exists(path):
            log.append(f"[TRANCO] refresh failed; using stale cache: {exc}")
            return True
        log.append(f"[TRANCO] unavailable; continuing without filtering: {exc}")
        return False


def load_tranco_suffix_matcher(config: TiConfiguration, log: list[str]) -> DomainSuffixMatcher:
    if not ensure_tranco_csv(config, log):
        return DomainSuffixMatcher()
    suffixes: set[str] = set()
    path = tranco_csv_path(config)
    with open(path, "r", encoding="utf-8", newline="") as csv_file:
        reader = csv.reader(csv_file)
        for row in reader:
            if len(row) < 2:
                continue
            domain = normalize_domain(row[1])
            if domain:
                suffixes.add(domain)
    log.append(f"[TRANCO] loaded_suffixes={len(suffixes)}")
    return DomainSuffixMatcher(suffixes)


def filter_tranco_domains(iocs: IocStore, matcher: DomainSuffixMatcher) -> int:
    if len(matcher) == 0:
        return 0
    before = len(iocs.domains)
    iocs.domains = {domain for domain in iocs.domains if not matcher.matches(domain)}
    return before - len(iocs.domains)


def fetch_taxii_pages(config: TiConfiguration, log: list[str]) -> Iterator[tuple[dict[str, Any], int]]:
    """Yield TAXII pages progressively using the server-provided ``next`` token."""
    if not config.taxii_url:
        raise RuntimeError("TAXII URL is not configured")

    next_token = None
    page_number = 0

    while True:
        page_number += 1
        params = {"next": next_token} if next_token else None
        response = requests.get(
            config.taxii_url,
            params=params,
            headers=TAXII_HEADERS,
            timeout=config.request_timeout_seconds,
        )
        response.raise_for_status()

        data = response.json()
        objects = data.get("objects", [])
        more = bool(data.get("more"))
        next_token = data.get("next")

        log.append(f"[FETCH] page={page_number} objects={len(objects)} more={more}")
        yield data, page_number

        if not more or not next_token:
            break


def queue_retro_jobs(config: TiConfiguration, additions: Iterable[tuple[str, str]], now) -> int:
    """Queue retro-hunt work for IOC values introduced by the latest snapshot."""
    if not config.retrohunt_enabled:
        return 0

    from datetime import timedelta

    window_start = now - timedelta(days=config.retrohunt_lookback_days)
    queued = 0

    for kind, value in sorted(additions):
        if kind == IocKind.HASH and not config.retrohunt_hash_search_enabled:
            continue

        RetroJob.objects.update_or_create(
            kind=kind,
            value=value,
            defaults={
                "window_start": window_start,
                "window_end": now,
                "queued_at": now,
                # Empty batch/cursor marks the job as unclaimed.
                "batch_id": "",
                "cursor": None,
                "last_error": "",
                "attempts": 0,
            },
        )
        queued += 1

    return queued


def delete_stale_opencti_indicators(snapshot_time) -> int:
    """Delete OpenCTI rows not refreshed during the current snapshot.

    Current rows are upserted with the same ``last_seen`` timestamp. Older OpenCTI
    rows therefore represent values that disappeared from the feed and can be
    deleted without building a large ``NOT IN`` query.
    """
    deleted, _details = (
        Indicator.objects
        .filter(source=OPENCTI_SOURCE, last_seen__lt=snapshot_time)
        .delete()
    )
    return deleted


def persist_iocs(config: TiConfiguration, iocs: IocStore, log: list[str]) -> int:
    """Persist the new snapshot, queue new IOC values, and delete stale rows.

    ``Indicator`` is a current-state table: values removed from OpenCTI are removed
    locally after retro-hunt jobs for new values have been queued.
    """
    now = timezone.now()
    current = iocs.keys()
    previous_current = set(
        Indicator.objects
        .filter(source=OPENCTI_SOURCE)
        .values_list("kind", "value")
    )

    first_snapshot_seen = config.opencti_initial_snapshot_seen

    if not first_snapshot_seen and not config.retrohunt_queue_existing_on_first_run:
        additions: set[tuple[str, str]] = set()
    elif not first_snapshot_seen:
        additions = current
    else:
        additions = current - previous_current

    with transaction.atomic():
        # Queue before cleanup so new IOC values survive even if the source row is
        # later removed from the current Indicator snapshot.
        queued = queue_retro_jobs(config, additions, now)

        for kind, value in sorted(current):
            Indicator.objects.update_or_create(
                kind=kind,
                value=value,
                defaults={
                    "source": OPENCTI_SOURCE,
                    "last_seen": now,
                },
            )

        deleted_stale = delete_stale_opencti_indicators(now)

        if not first_snapshot_seen:
            TiConfiguration.objects.filter(pk=config.pk).update(
                opencti_initial_snapshot_seen=True,
                updated_at=timezone.now(),
            )
            config.opencti_initial_snapshot_seen = True

    log.append(
        f"[DB] current={len(current)} additions={len(additions)} "
        f"retro_jobs={queued} deleted_stale={deleted_stale}"
    )
    return queued


def run_taxii_fetch(triggered_by: str = "scheduled", celery_task_id: str = "") -> FetchRun:
    config = TiConfiguration.load()
    run = FetchRun.objects.create(status=RunStatus.RUNNING, triggered_by=triggered_by, celery_task_id=celery_task_id)
    log: list[str] = []
    started = time.time()
    iocs = IocStore()
    total_objects = 0
    total_indicators = 0
    skipped_indicators = 0
    tranco_excluded_domains = 0
    try:
        matcher = load_tranco_suffix_matcher(config, log)
        for page, _page_number in fetch_taxii_pages(config, log):
            objects = page.get("objects", [])
            for obj in objects:
                total_objects += 1
                if not isinstance(obj, dict) or obj.get("type") != "indicator":
                    continue
                total_indicators += 1
                accepted = extract_from_indicator(obj, iocs)
                if accepted == 0:
                    skipped_indicators += 1
        # Do not replace the current export set with an empty feed response.
        if total_indicators == 0:
            raise RuntimeError("TAXII fetch returned zero indicators; refusing to replace IOC snapshot")

        # Tranco filtering happens after extraction so fetch metrics still reflect
        # the original feed content.
        tranco_excluded_domains = filter_tranco_domains(iocs, matcher)
        queued = persist_iocs(config, iocs, log)
        elapsed = time.time() - started
        log.append(
            f"[DONE] elapsed={elapsed:.1f}s ips={len(iocs.ips)} domains={len(iocs.domains)} "
            f"hashes={len(iocs.hashes)} local_excluded={iocs.local_excluded}"
        )
        run.status = RunStatus.SUCCESS
        run.finished_at = timezone.now()
        run.total_objects = total_objects
        run.total_indicators = total_indicators
        run.skipped_indicators = skipped_indicators
        run.ips = len(iocs.ips)
        run.domains = len(iocs.domains)
        run.hashes = len(iocs.hashes)
        run.tranco_excluded_domains = tranco_excluded_domains
        run.queued_retro_jobs = queued
        run.log = "\n".join(log)
        run.save(update_fields=[
            "status", "finished_at", "total_objects", "total_indicators", "skipped_indicators",
            "ips", "domains", "hashes", "tranco_excluded_domains", "queued_retro_jobs", "log",
        ])
        return run
    except Exception as exc:
        run.status = RunStatus.FAILED
        run.finished_at = timezone.now()
        run.total_objects = total_objects
        run.total_indicators = total_indicators
        run.skipped_indicators = skipped_indicators
        run.tranco_excluded_domains = tranco_excluded_domains
        run.error = str(exc)
        log.append(f"[ERROR] {exc}")
        run.log = "\n".join(log)
        run.save()
        raise
