from django.conf.urls import url
from .views import CallbackList, CallbackDetail
from .views import PortList, PortDetail
from .views import SecretList
from .views import StatusView
from .views import HandlerList
from .views import BlacklistList, BlacklistDetail
from .views import TokenList, ClientDetail
from .views import ClientList
from .views import SettingsView
from .permissions import ClientUserPermissions

from rest_framework.decorators import renderer_classes, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import BasicAuthentication
from rest_framework.response import Response
from rest_framework.schemas import SchemaGenerator
from rest_framework.views import APIView
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
   openapi.Info(
      title="Catcher API",
      default_version='v1',
      description="Callback catcher REST API",
   ),
   public=True,
   permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    url(r'^$', schema_view.with_ui('swagger', cache_timeout=0), name='schema-swagger-ui'),
    url(r'^client/$', ClientList.as_view()),
    url(r'^client/(?P<pk>[0-9]+)/$', ClientDetail.as_view()),
    url(r'^client/(?P<pk>[0-9]+)/tokens$', TokenList.as_view()),
    url(r'^handler/$', HandlerList.as_view()),
    url(r'^callback/$', CallbackList.as_view()),
    url(r'^callback/(?P<pk>[0-9]+)/$', CallbackDetail.as_view()),
    url(r'^port/(?P<pk>[0-9]+)/$', PortDetail.as_view()),
    url(r'^port/$', PortList.as_view()),
    url(r'^blacklist/$', BlacklistList.as_view()),
    url(r'^blacklist/(?P<pk>[0-9]+)/$', BlacklistDetail.as_view()),
    url(r'^secret/$', SecretList.as_view()),
    url(r'^status/$', StatusView.as_view()),
    url(r'^settings/$', SettingsView.as_view()),
]
