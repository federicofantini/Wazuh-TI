from __future__ import annotations

from django.urls import path

from threatintel.views import export_iocs, export_retrohunt_events

urlpatterns = [
    path("opencti_ips", export_iocs, {"kind": "ip"}, name="opencti_ips"),
    path("opencti_domains", export_iocs, {"kind": "domain"}, name="opencti_domains"),
    path("opencti_file_hashes", export_iocs, {"kind": "hash"}, name="opencti_file_hashes"),
    path("opencti_retrohunt_events.json", export_retrohunt_events, name="opencti_retrohunt_events"),
]
