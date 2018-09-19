from django.conf.urls import include
from django.conf.urls import url
from django.contrib import admin
from django.views.generic.base import RedirectView

from .views import index, script

favicon_view = RedirectView.as_view(url='/static/favicon.ico', permanent=True)

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api/', include('restapi.urls')),
    url(r'^script.js', script, name="script"),
    url(r'^favicon\.ico$', favicon_view),
    url(r'^', index, name="index"),
]
