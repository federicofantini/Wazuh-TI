#!/usr/bin/env python3
"""
Fetch OpenCTI TAXII indicators and export them as Wazuh CDB lists.

Output files:
- opencti-ips
- opencti-domains
- opencti-file-hashes

The script intentionally does not parse full STIX 2.1.
It prefers OpenCTI observable_values and uses STIX pattern parsing only
as a small fallback when no valid IOC was extracted from observable_values.

Extra domain filtering:
- Downloads the latest Tranco full list.
- Caches it under variable TRANCO_DIR.
- Refreshes it when the local file is older than 14 days.
- Excludes OpenCTI domain IOCs matching Tranco entries.
- Tranco entries are treated as DNS suffixes:
  example.com excludes example.com and sub.example.com,
  but does not exclude badexample.com.
"""

import csv
import ipaddress
import os
import re
import time
import requests
from dataclasses import dataclass, field
from typing import Any, Iterator
from urllib.parse import urlparse


TAXII_URL = "..."

OUTPUT_DIR = "/home/opencti-ti/iocs"
OUTPUT_FILES = {
    "ip": os.path.join(OUTPUT_DIR, "opencti_ips"),
    "domain": os.path.join(OUTPUT_DIR, "opencti_domains"),
    "hash": os.path.join(OUTPUT_DIR, "opencti_file_hashes"),
}

IOC_TAG = "opencti"
REQUEST_TIMEOUT_SECONDS = 30
PROGRESS_EVERY_INDICATORS = 5000


# ===================== TRANCO CONFIG =====================

TRANCO_BASE_URL = "https://tranco-list.eu"
TRANCO_LATEST_LIST_URL = f"{TRANCO_BASE_URL}/latest_list"

TRANCO_DIR = "/home/opencti-ti/bin"
TRANCO_CSV_PATH = os.path.join(TRANCO_DIR, "tranco_latest_full.csv")
TRANCO_ID_PATH = os.path.join(TRANCO_DIR, "tranco_latest_id.txt")

TRANCO_MAX_AGE_SECONDS = 14 * 24 * 60 * 60
TRANCO_CHUNK_SIZE_BYTES = 1024 * 1024

TRANCO_CONNECT_TIMEOUT_SECONDS = 15
TRANCO_READ_TIMEOUT_SECONDS = 300
TRANCO_DOWNLOAD_RETRIES = 3
TRANCO_RETRY_SLEEP_SECONDS = 5

TRANCO_LIST_ID_RE = re.compile(r"/list/([A-Za-z0-9]+)(?:$|[?#])")
TRANCO_DOWNLOAD_HREF_RE = re.compile(r'href=["\']/download/([A-Za-z0-9]+)/full["\']')
TRANCO_PAGE_ID_RE = re.compile(
    r"Tranco list with ID\s*<[^>]*>\s*([A-Za-z0-9]+)",
    re.IGNORECASE,
)


# ===================== REGEX =====================

QUOTED_VALUE_RE = re.compile(r"'([^']+)'")

HASH_PATTERN_RE = re.compile(
    r"file:hashes(?:\.'?([A-Za-z0-9_-]+)'?)?\s*=\s*'([^']+)'",
    re.IGNORECASE,
)

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$",
    re.IGNORECASE,
)

HEX_RE = re.compile(r"^[a-fA-F0-9]+$")


# ===================== DOMAIN SUFFIX MATCHER =====================

class DomainSuffixMatcher:
    """
    Efficient suffix matcher for domain allow/block lists.

    Tranco mainly contains registrable/popular domains, not every possible
    subdomain. Therefore a Tranco entry such as "example.com" must exclude:
    - example.com
    - a.example.com
    - b.a.example.com

    But it must not exclude:
    - badexample.com
    """

    def __init__(self, suffixes: set[str] | None = None) -> None:
        self._suffixes = suffixes or set()

    def __len__(self) -> int:
        return len(self._suffixes)

    def matches(self, domain: str) -> bool:
        """Return True when domain is exactly, or is below, a known suffix."""
        normalized = normalize_domain(domain)
        if not normalized:
            return False

        labels = normalized.split(".")

        for offset in range(len(labels)):
            candidate_suffix = ".".join(labels[offset:])
            if candidate_suffix in self._suffixes:
                return True

        return False


# ===================== IOC STORE =====================

@dataclass
class IocStore:
    """Unique IOC values grouped by output file type."""

    ips: set[str] = field(default_factory=set)
    domains: set[str] = field(default_factory=set)
    hashes: set[str] = field(default_factory=set)

    def add_ip(self, value: Any) -> bool:
        ip_value = normalize_ip(value)
        if not ip_value:
            return False

        self.ips.add(ip_value)
        return True

    def add_domain(self, value: Any) -> bool:
        domain = normalize_domain(value)
        if not domain:
            return False

        self.domains.add(domain)
        return True

    def add_hash(self, value: Any) -> bool:
        digest = normalize_hash(value)
        if not digest:
            return False

        self.hashes.add(digest.lower())
        self.hashes.add(digest.upper())
        return True

    def add_host(self, value: Any) -> str | None:
        """
        Add a host to the correct IOC list.

        URL hosts may be either IP addresses or domain names.
        IP validation must run before domain validation.
        """
        if self.add_ip(value):
            return "ip"

        if self.add_domain(value):
            return "domain"

        return None

    def total_count(self) -> int:
        return len(self.ips) + len(self.domains) + len(self.hashes)

    def output_values(self, kind: str) -> set[str]:
        if kind == "ip":
            return self.ips
        if kind == "domain":
            return self.domains
        if kind == "hash":
            return self.hashes

        raise ValueError(f"Unsupported IOC kind: {kind}")


# ===================== NORMALIZATION =====================

def clean_string(value: Any) -> str | None:
    """Return a stripped string or None."""
    if not isinstance(value, str):
        return None

    value = value.strip()
    return value or None


def normalize_type(value: Any) -> str:
    """Normalize observable type names for comparison."""
    value = clean_string(value)
    if not value:
        return ""

    return value.lower().replace("_", "-").replace(" ", "-")


def normalize_ip(value: Any) -> str | None:
    """Validate and normalize an IPv4 or IPv6 address."""
    value = clean_string(value)
    if not value:
        return None

    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        return None


def normalize_domain(value: Any) -> str | None:
    """Validate and normalize a domain name."""
    value = clean_string(value)
    if not value:
        return None

    domain = value.lower().rstrip(".")

    # Do not allow IP addresses to be stored as domains.
    if normalize_ip(domain):
        return None

    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return None

    if not DOMAIN_RE.match(domain):
        return None

    return domain


def normalize_hash(value: Any) -> str | None:
    """Validate and normalize MD5, SHA1, SHA256 or SHA512 hashes."""
    value = clean_string(value)
    if not value:
        return None

    digest = value.lower()

    if len(digest) not in {32, 40, 64, 128}:
        return None

    if not HEX_RE.match(digest):
        return None

    return digest


def extract_host_from_url(value: Any) -> str | None:
    """Extract a hostname or IP host from a URL-like value."""
    value = clean_string(value)
    if not value:
        return None

    parsed = urlparse(value)

    # urlparse("example.com/path") treats it as a path, not as a netloc.
    if not parsed.hostname and "://" not in value:
        parsed = urlparse(f"http://{value}")

    if not parsed.hostname:
        return None

    return parsed.hostname.strip().lower().rstrip(".") or None


# ===================== OPENCTI IOC EXTRACTION =====================

def iter_observable_values(indicator: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Yield OpenCTI observable_values from top-level and extension fields."""
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
        if not isinstance(values, list):
            continue

        for value in values:
            if isinstance(value, dict):
                yield value


def extract_from_observable(observable: dict[str, Any], iocs: IocStore) -> int:
    """
    Extract valid IOCs from one OpenCTI observable_values entry.

    Returns the number of accepted IOC extractions.
    """
    observable_type = normalize_type(observable.get("type"))
    value = observable.get("value")

    if observable_type in {"ipv4-addr", "ipv6-addr"}:
        return int(iocs.add_ip(value))

    if observable_type in {"domain-name", "hostname"}:
        return int(iocs.add_host(value) is not None)

    if observable_type in {"url", "uri"}:
        host = extract_host_from_url(value)
        return int(iocs.add_host(host) is not None)

    if observable_type in {"stixfile", "file"}:
        hashes = observable.get("hashes")
        if not isinstance(hashes, dict):
            return 0

        accepted = 0

        for hash_value in hashes.values():
            if iocs.add_hash(hash_value):
                accepted += 1

        return accepted

    return 0


def extract_from_pattern(pattern: Any, iocs: IocStore) -> int:
    """
    Minimal fallback for simple STIX patterns.

    This is only used when observable_values produced no valid IOC.
    """
    pattern = clean_string(pattern)
    if not pattern:
        return 0

    hash_match = HASH_PATTERN_RE.search(pattern)
    if hash_match:
        return int(iocs.add_hash(hash_match.group(2)))

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
        host = extract_host_from_url(value)
        return int(iocs.add_host(host) is not None)

    return 0


def extract_from_indicator(indicator: dict[str, Any], iocs: IocStore) -> int:
    """
    Extract IOCs from an indicator.

    observable_values is the primary source.
    STIX pattern parsing is used only as fallback.
    """
    accepted = 0

    for observable in iter_observable_values(indicator):
        accepted += extract_from_observable(observable, iocs)

    if accepted == 0:
        accepted += extract_from_pattern(indicator.get("pattern"), iocs)

    return accepted


# ===================== TRANCO DOWNLOAD / CACHE =====================

def file_is_older_than(path: str, max_age_seconds: int) -> bool:
    """Return True when path is missing or older than max_age_seconds."""
    try:
        mtime = os.path.getmtime(path)
    except FileNotFoundError:
        return True

    return (time.time() - mtime) > max_age_seconds


def extract_tranco_list_id(page_url: str, html: str) -> str | None:
    """
    Extract the Tranco list ID from the /latest_list redirect target or HTML.

    Typical latest_list behavior:
    - HTTP 303 redirect to /list/<ID>
    - final HTML contains links like /download/<ID>/full
    """
    url_match = TRANCO_LIST_ID_RE.search(page_url)
    if url_match:
        return url_match.group(1)

    download_match = TRANCO_DOWNLOAD_HREF_RE.search(html)
    if download_match:
        return download_match.group(1)

    page_match = TRANCO_PAGE_ID_RE.search(html)
    if page_match:
        return page_match.group(1)

    return None


def resolve_latest_tranco_list_id() -> str:
    """
    Resolve the current standard Tranco daily list ID.

    /latest_list returns an HTTP redirect to the current list page.
    requests follows that redirect, like curl -L.
    """
    response = requests.get(
        TRANCO_LATEST_LIST_URL,
        timeout=(TRANCO_CONNECT_TIMEOUT_SECONDS, TRANCO_READ_TIMEOUT_SECONDS),
        allow_redirects=True,
    )
    response.raise_for_status()

    list_id = extract_tranco_list_id(response.url, response.text)
    if not list_id:
        raise RuntimeError(
            "Could not extract Tranco list ID from latest_list response "
            f"url={response.url!r}"
        )

    return list_id


def tranco_download_url(list_id: str) -> str:
    """Return the full-list CSV download URL for a Tranco list ID."""
    return f"{TRANCO_BASE_URL}/download/{list_id}/full"


def write_tranco_id(path: str, list_id: str) -> None:
    """Persist the Tranco list ID matching the cached CSV."""
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output:
        output.write(f"{list_id}\n")

    os.replace(tmp_path, path)


def read_tranco_id(path: str = TRANCO_ID_PATH) -> str | None:
    """Read the cached Tranco list ID, if available."""
    try:
        with open(path, "r", encoding="utf-8") as input_file:
            return clean_string(input_file.readline())
    except FileNotFoundError:
        return None


def download_tranco_csv(path: str) -> str:
    """
    Download the latest Tranco full CSV atomically.

    Returns the Tranco list ID that was downloaded.
    """
    os.makedirs(os.path.dirname(path), exist_ok=True)

    tmp_path = f"{path}.tmp"
    last_error: Exception | None = None

    for attempt in range(1, TRANCO_DOWNLOAD_RETRIES + 1):
        try:
            list_id = resolve_latest_tranco_list_id()
            download_url = tranco_download_url(list_id)

            print(
                f"[TRANCO] Downloading latest list {list_id}: "
                f"{download_url} -> {path} "
                f"(attempt {attempt}/{TRANCO_DOWNLOAD_RETRIES})",
                flush=True,
            )

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
            write_tranco_id(TRANCO_ID_PATH, list_id)

            print(f"[TRANCO] Download completed: list_id={list_id}", flush=True)
            return list_id

        except requests.RequestException as exc:
            last_error = exc

        except RuntimeError as exc:
            last_error = exc

        try:
            os.unlink(tmp_path)
        except FileNotFoundError:
            pass

        print(f"[TRANCO] WARNING: download attempt failed: {last_error}", flush=True)

        if attempt < TRANCO_DOWNLOAD_RETRIES:
            time.sleep(TRANCO_RETRY_SLEEP_SECONDS)

    raise RuntimeError(f"Tranco download failed after retries: {last_error}")


def ensure_tranco_csv(path: str = TRANCO_CSV_PATH) -> bool:
    """
    Ensure the cached Tranco CSV exists and is not older than 14 days.

    If refresh fails but an older local file exists, keep using the local copy so
    a temporary Tranco/network outage does not break the daily IOC export.

    If no local file exists, return False and let the caller continue without
    Tranco filtering instead of crashing the daily job.
    """
    if not file_is_older_than(path, TRANCO_MAX_AGE_SECONDS):
        age_days = (time.time() - os.path.getmtime(path)) / 86400
        cached_id = read_tranco_id() or "unknown"

        print(
            f"[TRANCO] Using cached CSV: {path} "
            f"list_id={cached_id} age={age_days:.1f}d",
            flush=True,
        )
        return True

    try:
        list_id = download_tranco_csv(path)
        print(f"[TRANCO] Cached latest CSV list_id={list_id}", flush=True)
        return True

    except Exception as exc:
        if os.path.exists(path):
            print(
                "[TRANCO] WARNING: refresh failed; using stale cached CSV: "
                f"{exc}",
                flush=True,
            )
            return True

        print(
            "[TRANCO] WARNING: download failed and no cached CSV exists; "
            "continuing without Tranco domain exclusions: "
            f"{exc}",
            flush=True,
        )
        return False


def load_tranco_suffix_matcher(path: str = TRANCO_CSV_PATH) -> DomainSuffixMatcher:
    """Load Tranco domains as suffixes for exact-domain and subdomain exclusion."""
    if not ensure_tranco_csv(path):
        return DomainSuffixMatcher()

    suffixes: set[str] = set()

    with open(path, "r", encoding="utf-8", newline="") as csv_file:
        reader = csv.reader(csv_file)

        for row in reader:
            # Tranco full CSV format without header:
            # rank,domain
            if len(row) < 2:
                continue

            domain = normalize_domain(row[1])
            if domain:
                suffixes.add(domain)

    print(f"[TRANCO] Loaded {len(suffixes)} domain suffix(es)", flush=True)
    return DomainSuffixMatcher(suffixes)


def filter_tranco_domains(iocs: IocStore, matcher: DomainSuffixMatcher) -> int:
    """Remove domains matching the Tranco suffix matcher from the domain IOC set."""
    if len(matcher) == 0 or not iocs.domains:
        return 0

    before = len(iocs.domains)

    iocs.domains = {
        domain
        for domain in iocs.domains
        if not matcher.matches(domain)
    }

    return before - len(iocs.domains)


# ===================== TAXII FETCH =====================

def fetch_taxii_pages() -> Iterator[tuple[dict[str, Any], int]]:
    """Yield TAXII pages from the configured collection."""
    next_token = None
    page_number = 0

    while True:
        page_number += 1
        url = TAXII_URL if not next_token else f"{TAXII_URL}?next={next_token}"

        print(f"[FETCH] Page {page_number}...", flush=True)

        response = requests.get(url, timeout=REQUEST_TIMEOUT_SECONDS)
        response.raise_for_status()

        data = response.json()
        objects = data.get("objects", [])
        more = bool(data.get("more"))
        next_token = data.get("next")

        print(
            f"[FETCH] Page {page_number} received: "
            f"{len(objects)} objects, more={more}",
            flush=True,
        )

        yield data, page_number

        if not more or not next_token:
            break


# ===================== OUTPUT =====================

def write_ioc_file(path: str, values: set[str]) -> None:
    """Write a Wazuh CDB list atomically."""
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as output:
        for value in sorted(values):
            output.write(f"{value}:{IOC_TAG}\n")

    os.replace(tmp_path, path)


def write_outputs(iocs: IocStore) -> None:
    """Write all IOC output files."""
    print("[WRITE] Writing output files...", flush=True)

    for kind, path in OUTPUT_FILES.items():
        values = iocs.output_values(kind)
        write_ioc_file(path, values)
        print(f"[WRITE] {kind}: {len(values)} item(s) -> {path}", flush=True)


# ===================== LOGGING =====================

def print_progress(
    page_number: int,
    total_objects: int,
    total_indicators: int,
    iocs: IocStore,
) -> None:
    """Print compact progress information."""
    print(
        "[PROGRESS] "
        f"page={page_number}, "
        f"objects={total_objects}, "
        f"indicators={total_indicators}, "
        f"ips={len(iocs.ips)}, "
        f"domains={len(iocs.domains)}, "
        f"hashes={len(iocs.hashes)}",
        flush=True,
    )


def print_summary(
    iocs: IocStore,
    total_objects: int,
    total_indicators: int,
    skipped_indicators: int,
    tranco_excluded_domains: int,
    elapsed_seconds: float,
) -> None:
    """Print final execution summary."""
    print(
        "\n[DONE] "
        f"objects={total_objects}, "
        f"indicators={total_indicators}, "
        f"skipped_indicators={skipped_indicators}, "
        f"tranco_excluded_domains={tranco_excluded_domains}, "
        f"unique_iocs={iocs.total_count()}, "
        f"ips={len(iocs.ips)}, "
        f"domains={len(iocs.domains)}, "
        f"hashes={len(iocs.hashes)}, "
        f"elapsed={elapsed_seconds:.1f}s",
        flush=True,
    )


# ===================== MAIN =====================

def main() -> None:
    started_at = time.time()

    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(TRANCO_DIR, exist_ok=True)

    iocs = IocStore()

    tranco_matcher = load_tranco_suffix_matcher()

    total_objects = 0
    total_indicators = 0
    skipped_indicators = 0

    print("[START] Fetching OpenCTI TAXII indicators...", flush=True)

    for page, page_number in fetch_taxii_pages():
        objects = page.get("objects", [])

        for obj in objects:
            total_objects += 1

            if not isinstance(obj, dict):
                continue

            if obj.get("type") != "indicator":
                continue

            total_indicators += 1

            accepted = extract_from_indicator(obj, iocs)
            if accepted == 0:
                skipped_indicators += 1

            if total_indicators % PROGRESS_EVERY_INDICATORS == 0:
                print_progress(page_number, total_objects, total_indicators, iocs)

    tranco_excluded_domains = filter_tranco_domains(iocs, tranco_matcher)

    print(
        f"[TRANCO] Excluded {tranco_excluded_domains} domain IOC(s) from CDB output",
        flush=True,
    )

    write_outputs(iocs)

    elapsed_seconds = time.time() - started_at

    print_summary(
        iocs=iocs,
        total_objects=total_objects,
        total_indicators=total_indicators,
        skipped_indicators=skipped_indicators,
        tranco_excluded_domains=tranco_excluded_domains,
        elapsed_seconds=elapsed_seconds,
    )


if __name__ == "__main__":
    main()