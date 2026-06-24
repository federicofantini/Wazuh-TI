from __future__ import annotations

from celery import shared_task

from threatintel.iocs import run_taxii_fetch
from threatintel.retrohunt import run_queue


@shared_task(bind=True, name="threatintel.tasks.fetch_opencti_iocs_task")
def fetch_opencti_iocs_task(self, triggered_by: str = "scheduled"):
    run = run_taxii_fetch(triggered_by=triggered_by, celery_task_id=self.request.id or "")
    return {"run_id": run.id, "status": run.status, "ips": run.ips, "domains": run.domains, "hashes": run.hashes}


@shared_task(bind=True, name="threatintel.tasks.run_retrohunt_queue_task")
def run_retrohunt_queue_task(self, triggered_by: str = "scheduled"):
    run = run_queue(triggered_by=triggered_by)
    return {"run_id": run.id, "status": run.status, "hits": run.hits, "emitted": run.emitted, "pending_after": run.pending_after}
