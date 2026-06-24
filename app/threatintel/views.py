"""HTTP export endpoints consumed by Wazuh.

Large IOC and retro-hunt exports are streamed instead of materialised in memory.
"""

from __future__ import annotations

import ipaddress
import json
import secrets
from collections.abc import Iterator

from django.http import HttpRequest, HttpResponse, StreamingHttpResponse
from django.views.decorators.http import require_GET

from threatintel.models import Indicator, IocKind, RetroHit, TiConfiguration

ENDPOINT_FILENAMES = {
    IocKind.IP: "opencti_ips",
    IocKind.DOMAIN: "opencti_domains",
    IocKind.HASH: "opencti_file_hashes",
}


def authorized(request: HttpRequest, config: TiConfiguration) -> bool:
    """Validate the export bearer token using constant-time comparison."""
    token = (config.export_api_token or "").strip()
    if not token:
        # No token configured: allow all requests. Useful during initial setup
        # but should not be left this way in a networked deployment.
        return True
    expected = f"Bearer {token}"
    return secrets.compare_digest(request.headers.get("Authorization", ""), expected)


def cdb_lines(kind: str, config: TiConfiguration) -> Iterator[str]:
    """Stream the current IOC snapshot in Wazuh CDB-list format."""
    values = (
        Indicator.objects
        .filter(kind=kind)
        .order_by("value")
        .values_list("value", flat=True)
    )

    for value in values.iterator(chunk_size=5000):
        if kind == IocKind.IP:
            try:
                ip = ipaddress.ip_address(value)
            except ValueError:
                continue

            value = str(ip)

            # Wazuh CDB lists use ':' as the key/value separator.
            # IPv6 literals contain ':', so the complete key must be quoted.
            if ip.version == 6:
                yield f'"{value}":{config.ioc_tag}\n'
                continue

        yield f"{value}:{config.ioc_tag}\n"

        if kind == IocKind.HASH:
            # Some Wazuh/Sysmon fields preserve uppercase hashes, while the
            # database stores one canonical lowercase value.
            upper = value.upper()
            if upper != value:
                yield f"{upper}:{config.ioc_tag}\n"


@require_GET
def export_iocs(request: HttpRequest, kind: str):
    if kind not in ENDPOINT_FILENAMES:
        return HttpResponse("unsupported IOC kind\n", status=404, content_type="text/plain")

    config = TiConfiguration.load()
    if not authorized(request, config):
        return HttpResponse("unauthorized\n", status=401, content_type="text/plain")

    response = StreamingHttpResponse(cdb_lines(kind, config), content_type="text/plain; charset=utf-8")
    response["Content-Disposition"] = f'inline; filename="{ENDPOINT_FILENAMES[kind]}"'
    response["Cache-Control"] = "no-store"
    return response


def retrohit_event(hit: RetroHit) -> dict:
    source = hit.raw_event.get("_source", {}) if isinstance(hit.raw_event, dict) else {}
    if not isinstance(source, dict):
        source = {}

    return {
        "retrohunt": {
            "source": "opencti",
            "match_type": "historical_ioc_match",
            "export_id": hit.pk,
            "kind": hit.kind,
            "value": hit.value,
            "historical": {
                "index": hit.index_name,
                "document_id": hit.document_id,
                "timestamp": hit.timestamp,
                "agent": source.get("agent", {}),
                "rule": source.get("rule", {}),
                "location": hit.location,
                "decoder": source.get("decoder", {}),
                "matched_fields": hit.matched_fields,
            },
        }
    }


@require_GET
def export_retrohunt_events(request: HttpRequest):
    """Stream retro-hunt matches as newline-delimited JSON events."""
    config = TiConfiguration.load()
    if not authorized(request, config):
        return HttpResponse("unauthorized\n", status=401, content_type="text/plain")

    def stream_lines():
        qs = RetroHit.objects.order_by("pk")
        for hit in qs.iterator(chunk_size=1000):
            yield json.dumps(retrohit_event(hit), separators=(",", ":")) + "\n"

    response = StreamingHttpResponse(stream_lines(), content_type="application/x-ndjson; charset=utf-8")
    response["Content-Disposition"] = 'inline; filename="opencti_retrohunt_events.json"'
    response["Cache-Control"] = "no-store"
    return response