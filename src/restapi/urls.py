from django.conf.urls import url
from views import CallbackList
from views import CallbackSecretList
from views import PortList, PortDetail
from views import StatusView
from views import HandlerList
from views import TokenList

urlpatterns = [
    url(r'^handler/$', HandlerList.as_view()),
    url(r'^callback/(?P<callbackid>[0-9]+)/secret/$', CallbackSecretList.as_view()),
    url(r'^callback/$', CallbackList.as_view()),
    url(r'^port/(?P<pk>[0-9]+)/$', PortDetail.as_view()),
    url(r'^port/$', PortList.as_view(),),
    url(r'^token/$', TokenList.as_view()), 
    url(r'^status/$', StatusView.as_view()),
]