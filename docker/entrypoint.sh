#!/usr/bin/env bash
set -euo pipefail

run_django_bootstrap() {
  echo "[entrypoint] Running Django bootstrap tasks."

  python manage.py migrate --noinput

  # Bootstrap the singleton TI configuration from environment variables only on first boot.
  # The command must skip execution when TiConfiguration already exists, otherwise later
  # changes made from Django Admin would be overwritten on every container restart.
  python manage.py bootstrap_ticonfig_from_env

  python manage.py collectstatic --noinput

  # Reconcile django-celery-beat periodic tasks after configuration bootstrap.
  # This ensures the TAXII fetch and retro-hunt schedules reflect the current admin config.
  python manage.py shell <<'INNER_PY'
from threatintel.models import TiConfiguration, sync_periodic_tasks_safe
sync_periodic_tasks_safe(TiConfiguration.load())
INNER_PY

  if [[ -n "${DJANGO_SUPERUSER_USERNAME:-}" && -n "${DJANGO_SUPERUSER_PASSWORD:-}" ]]; then
    python manage.py shell <<'INNER_PY'
import os
from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction

User = get_user_model()
username = os.environ["DJANGO_SUPERUSER_USERNAME"]
email = os.environ.get("DJANGO_SUPERUSER_EMAIL", "")
password = os.environ["DJANGO_SUPERUSER_PASSWORD"]

try:
    with transaction.atomic():
        user, created = User.objects.get_or_create(
            username=username,
            defaults={
                "email": email,
                "is_staff": True,
                "is_superuser": True,
                "is_active": True,
            },
        )
except IntegrityError:
    user = User.objects.get(username=username)
    created = False

changed = False

if email and user.email != email:
    user.email = email
    changed = True

if not user.is_staff or not user.is_superuser or not user.is_active:
    user.is_staff = True
    user.is_superuser = True
    user.is_active = True
    changed = True

# Password is set only when the superuser is created for the first time.
# Existing admin passwords are never overwritten on container restart/redeploy.
if created:
    user.set_password(password)
    changed = True

if changed:
    user.save()
INNER_PY
  fi
}

if [[ "${DJANGO_BOOTSTRAP:-false}" == "true" ]]; then
  run_django_bootstrap
else
  echo "[entrypoint] Skipping Django bootstrap tasks for this service."
fi

if [[ "${1:-}" == "gunicorn" ]]; then
  workers="${GUNICORN_WORKERS:-3}"
  timeout="${GUNICORN_TIMEOUT:-120}"
  exec "$@" --workers "$workers" --timeout "$timeout" --access-logfile - --error-logfile -
fi

exec "$@"