import os

from django.core.wsgi import get_wsgi_application

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "wazuh_ti.settings")

application = get_wsgi_application()
