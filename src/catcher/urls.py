from django.conf.urls import include
from django.conf.urls import url
from django.contrib import admin

from .views import index, script

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^api/', include('restapi.urls')),
    url(r'^script.js', script, name="script"),
    url(r'^', index, name="index"),
]
