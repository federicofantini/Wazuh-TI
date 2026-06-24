from __future__ import annotations

import os

from django.core.management.base import BaseCommand

from threatintel.models import TiConfiguration


def env_value(name: str) -> str | None:
    value = os.getenv(name)
    if value is None:
        return None

    value = value.strip()
    return value if value else None


def env_bool(name: str) -> bool | None:
    value = env_value(name)
    if value is None:
        return None

    normalized = value.lower()

    if normalized in {"1", "true", "yes", "y", "on"}:
        return True

    if normalized in {"0", "false", "no", "n", "off"}:
        return False

    raise ValueError(f"{name} must be a boolean value")


class Command(BaseCommand):
    help = "Bootstrap the singleton TiConfiguration from environment variables on first boot only."

    def handle(self, *args, **options):
        config, created = TiConfiguration.objects.get_or_create(pk=1)

        if not created:
            self.stdout.write(
                self.style.WARNING(
                    "TiConfiguration already exists; environment bootstrap skipped."
                )
            )
            return

        env_mapping = {
            "export_api_token": env_value("WAZUH_TI_EXPORT_API_TOKEN"),
            "taxii_url": env_value("WAZUH_TI_TAXII_URL"),
            "wazuh_indexer_url": env_value("WAZUH_TI_WAZUH_INDEXER_URL"),
            "wazuh_indexer_username": env_value("WAZUH_TI_WAZUH_INDEXER_USERNAME"),
            "wazuh_indexer_password": env_value("WAZUH_TI_WAZUH_INDEXER_PASSWORD"),
        }

        bool_mapping = {
            "retrohunt_queue_existing_on_first_run": env_bool(
                "WAZUH_TI_RETROHUNT_QUEUE_EXISTING_ON_FIRST_RUN"
            ),
            "wazuh_indexer_verify_tls": env_bool(
                "WAZUH_TI_WAZUH_INDEXER_VERIFY_TLS"
            ),
        }

        updated_fields: list[str] = []

        for field_name, value in env_mapping.items():
            if value is None:
                continue

            setattr(config, field_name, value)
            updated_fields.append(field_name)

        for field_name, value in bool_mapping.items():
            if value is None:
                continue

            setattr(config, field_name, value)
            updated_fields.append(field_name)

        if updated_fields:
            config.save()
            self.stdout.write(
                self.style.SUCCESS(
                    "TiConfiguration bootstrapped from environment: "
                    + ", ".join(sorted(updated_fields))
                )
            )
        else:
            self.stdout.write(
                self.style.WARNING(
                    "TiConfiguration created with model defaults; no bootstrap environment variables were set."
                )
            )