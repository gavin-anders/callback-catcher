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
from rest_framework_swagger.renderers import SwaggerUIRenderer, OpenAPIRenderer
from rest_framework_swagger.views import get_swagger_view

class SwaggerSchemaView(APIView):
    title='Callback Catcher API'
    authentication_classes = [BasicAuthentication, ]
    permission_classes = [IsAuthenticated, ]
    renderer_classes = [SwaggerUIRenderer, OpenAPIRenderer]

    def get(self, request):
        generator = SchemaGenerator()
        schema = generator.get_schema(request=request)
        return Response(schema)

urlpatterns = [
    url(r'^$', SwaggerSchemaView.as_view()),
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