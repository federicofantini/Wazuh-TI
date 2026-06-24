#!/usr/bin/env python3
import hashlib
import json
import os
import ssl
import tempfile
from pathlib import Path
from urllib.request import Request, urlopen


# Unprivileged Wazuh-TI downloader.
# Run as opencti-ti.
# This script only downloads artifacts into /home/opencti-ti/iocs.
# It never writes to /var/ossec and never restarts Wazuh.

WAZUH_TI_BASE_URL = "http://127.0.0.1:8000"
WAZUH_TI_TOKEN = "change-me"
OUTPUT_DIR = Path("/home/opencti-ti/iocs")

INSECURE_TLS = False
TIMEOUT_SECONDS = 60

CDB_FILES = (
    "opencti_ips",
    "opencti_domains",
    "opencti_file_hashes",
)

RETROHUNT_FILE = "opencti_retrohunt_events.json"
RETROHUNT_STATE_FILE = OUTPUT_DIR / ".opencti_retrohunt_last_hash"


def http_get(name: str, destination: Path) -> None:
    url = f"{WAZUH_TI_BASE_URL.rstrip('/')}/{name}"
    print(f"[Wazuh-TI] Downloading {url}")

    request = Request(
        url,
        headers={"Authorization": f"Bearer {WAZUH_TI_TOKEN}"},
    )

    context = ssl._create_unverified_context() if INSECURE_TLS else None

    with urlopen(request, timeout=TIMEOUT_SECONDS, context=context) as response:
        destination.write_bytes(response.read())


def split_cdb_line(line: str) -> tuple[str, str]:
    """Split one Wazuh CDB source-list line.

    Wazuh uses ':' as the key/value separator. If the key itself contains ':',
    for example an IPv6 address, the full key must be quoted:

        "2001:db8::1":opencti
    """
    if line.startswith('"'):
        end_quote = line.find('"', 1)
        if end_quote == -1:
            raise ValueError("quoted CDB key is not closed")

        if len(line) <= end_quote + 1 or line[end_quote + 1] != ":":
            raise ValueError("quoted CDB key must be followed by ':'")

        key = line[1:end_quote]
        value = line[end_quote + 2:]
    else:
        if line.count(":") != 1:
            raise ValueError("unquoted CDB lines must contain exactly one ':' separator")

        key, separator, value = line.partition(":")
        if separator != ":":
            raise ValueError("missing ':' separator")

    if not key:
        raise ValueError("empty CDB key")

    return key, value


def validate_cdb(path: Path) -> None:
    if not path.exists():
        raise SystemExit(f"[Wazuh-TI] ERROR: {path.name} was not downloaded")

    if path.stat().st_size == 0:
        print(f"[Wazuh-TI] WARNING: {path.name} is empty; staging an empty CDB source list")
        return

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                split_cdb_line(line)
            except ValueError as exc:
                raise SystemExit(
                    f"[Wazuh-TI] ERROR: {path.name}:{line_number} is not a valid CDB source line: {exc}"
                ) from exc


def normalize_json_line(line: str) -> str:
    data = json.loads(line)
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


def line_hash(line: str) -> str:
    return hashlib.sha256(normalize_json_line(line).encode("utf-8")).hexdigest()


def read_jsonl(path: Path) -> list[str]:
    events: list[str] = []

    if not path.exists() or path.stat().st_size == 0:
        return events

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                normalize_json_line(line)
            except json.JSONDecodeError as exc:
                raise SystemExit(
                    f"[Wazuh-TI] ERROR: invalid JSONL in {path.name}:{line_number}: {exc}"
                ) from exc

            events.append(line)

    return events


def write_retrohunt_diff(downloaded_path: Path, output_path: Path) -> None:
    # The Django endpoint streams the full RetroHit history on every call.
    # To avoid replaying old events into the Wazuh-monitored log, we track the
    # SHA-256 of the last exported line. On each run we scan forward to find that
    # line and write only the tail after it. If the hash is not found (e.g. after
    # a database rebuild), we fall back to exporting everything.
    events = read_jsonl(downloaded_path)

    last_hash = ""
    if RETROHUNT_STATE_FILE.exists():
        last_hash = RETROHUNT_STATE_FILE.read_text(encoding="utf-8").strip()

    start_index = 0
    if last_hash:
        for index, event in enumerate(events):
            if line_hash(event) == last_hash:
                start_index = index + 1
                break

    new_events = events[start_index:]

    with output_path.open("w", encoding="utf-8") as handle:
        for event in new_events:
            handle.write(event + "\n")

    if events:
        RETROHUNT_STATE_FILE.write_text(line_hash(events[-1]) + "\n", encoding="utf-8")
        os.chmod(RETROHUNT_STATE_FILE, 0o600)

    os.chmod(output_path, 0o640)
    print(f"[Wazuh-TI] Staged {output_path} ({len(new_events)} new events)")


def stage_file(source: Path, destination: Path) -> None:
    destination.write_bytes(source.read_bytes())
    os.chmod(destination, 0o640)

    lines = sum(1 for _ in destination.open("r", encoding="utf-8")) if destination.stat().st_size else 0
    print(f"[Wazuh-TI] Staged {destination} ({lines} lines)")


def main() -> int:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory() as tmp:
        tmp_dir = Path(tmp)

        for name in CDB_FILES:
            downloaded = tmp_dir / name
            staged = OUTPUT_DIR / name

            http_get(name, downloaded)
            validate_cdb(downloaded)
            stage_file(downloaded, staged)

        downloaded_retrohunt = tmp_dir / RETROHUNT_FILE
        staged_retrohunt = OUTPUT_DIR / RETROHUNT_FILE

        http_get(RETROHUNT_FILE, downloaded_retrohunt)
        write_retrohunt_diff(downloaded_retrohunt, staged_retrohunt)

    print("[Wazuh-TI] Done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())