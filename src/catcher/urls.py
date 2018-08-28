"""catcher URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.9/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Import the include() function: from django.conf.urls import url, include
    3. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from django.conf.urls import include
from django.conf.urls import url
from django.contrib import admin

from .views import index
from .views import CallbackView, PortView, SecretView, TokenView

urlpatterns = [
    url(r'^admin/', admin.site.urls),
    url(r'^secrets/', SecretView.as_view(), name="secret"),
    url(r'^tokens/', TokenView.as_view(), name="token"),
    url(r'^callbacks/', CallbackView.as_view(), name="callback"),
    url(r'^ports/', PortView.as_view(), name="port"),
    url(r'^api/', include('restapi.urls')),
    url(r'^$', index, name="index"),
]
