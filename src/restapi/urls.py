from django.conf.urls import url
from .views import CallbackList, CallbackDetail
from .views import PortList, PortDetail
from .views import SecretList, SecretDetail
from .views import StatusView
from .views import HandlerList
from .views import TokenList
from rest_framework_swagger.views import get_swagger_view

from rest_framework_swagger.renderers import OpenAPIRenderer, SwaggerUIRenderer
from rest_framework.decorators import api_view, renderer_classes, permission_classes
from rest_framework.permissions import IsAuthenticated
from rest_framework import response, schemas

schema_view = get_swagger_view(title='Callback Catcher API')

#@api_view()
#@permission_classes((IsAuthenticated, ))
#@renderer_classes([SwaggerUIRenderer, OpenAPIRenderer])
#def schema_view(request):
#    generator = schemas.SchemaGenerator(title='Callback Catcher API', url='')
#    return response.Response(generator.get_schema(request=request))

urlpatterns = [
    url(r'^$', schema_view),
    url(r'^handler/$', HandlerList.as_view()),
    url(r'^callback/(?P<id>[0-9]+)$', CallbackDetail.as_view()),
    url(r'^callback/$', CallbackList.as_view()),
    url(r'^port/(?P<pk>[0-9]+)/$', PortDetail.as_view()),
    url(r'^port/$', PortList.as_view(),),
    url(r'^token/$', TokenList.as_view()),
    url(r'^secret/(?P<id>[0-9]+)/$', SecretDetail.as_view()),
    url(r'^secret/$', SecretList.as_view()),
    url(r'^status/$', StatusView.as_view()),
]