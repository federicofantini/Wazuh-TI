from django.contrib import admin
from django.http import JsonResponse
from django.urls import include, path
from django.views.generic import RedirectView


admin.site.site_header = "Wazuh-TI"
admin.site.site_title = "Wazuh-TI Admin"
admin.site.index_title = "Threat Intelligence administration"


def health(_request):
    return JsonResponse({"status": "ok"})


urlpatterns = [
    path("", RedirectView.as_view(url="/admin/", permanent=False), name="home"),
    path("admin/", admin.site.urls),
    path("health/", health, name="health"),
    path("", include("threatintel.urls")),
]
