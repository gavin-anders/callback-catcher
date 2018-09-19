from django.conf.urls import url
from .views import CallbackList
from .views import PortList, PortDetail
from .views import SecretList
from .views import StatusView
from .views import HandlerList, HandlerDetail
from rest_framework_swagger.views import get_swagger_view

from rest_framework.decorators import renderer_classes, permission_classes, authentication_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import BasicAuthentication
from rest_framework.response import Response
from rest_framework.schemas import SchemaGenerator
from rest_framework.views import APIView
from rest_framework_swagger.renderers import SwaggerUIRenderer

class SwaggerSchemaView(APIView):
    title='Callback Catcher API'
    authentication_classes = [BasicAuthentication, ]
    permission_classes = [IsAuthenticated, ]
    renderer_classes = [SwaggerUIRenderer, ]

    def get(self, request):
        generator = SchemaGenerator()
        schema = generator.get_schema(request=request)
        return Response(schema)

urlpatterns = [
    url(r'^$', SwaggerSchemaView.as_view()),
    url(r'^handler/$', HandlerList.as_view()),
    url(r'^handler/(?P<pk>[0-9]+)/$', HandlerDetail.as_view()),
    url(r'^callback/$', CallbackList.as_view()),
    url(r'^port/(?P<pk>[0-9]+)/$', PortDetail.as_view()),
    url(r'^port/$', PortList.as_view(),),
    url(r'^secret/$', SecretList.as_view()),
    url(r'^status/$', StatusView.as_view()),
]