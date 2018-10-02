from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django import forms

from rest_framework import status, generics, authentication, exceptions, permissions
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from rest_framework.views import APIView
from rest_framework.mixins import DestroyModelMixin, ListModelMixin

from django_filters import rest_framework as filters

from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR
from catcher.utils import kill_process
from catcher import settings as SETTINGS
from catcher.config import CatcherConfigParser
from catcher.models import Handler, Callback, Fingerprint, Port, Secret, Handler, Blacklist

from .serializers import CallbackSerializer
from .serializers import PortSerializer, SecretSerializer, HandlerSerializer, BlacklistSerializer

from .filters import CallbackFilter, SecretFilter

import logging
import base64

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def start_port(number, protocol, ssl, handler=None):
    process = Service(LISTEN_IP, number, protocol, ssl)
    if handler:
        process.set_handler(handler.filename, handler.settings)
    process.start()
    return process.pid

class CallbackList(generics.ListAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Callback.objects.all().order_by('-pk')
    serializer_class = CallbackSerializer
    paginate_by = 100
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = CallbackFilter
    
class PortList(generics.ListCreateAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Port.objects.filter(pid__isnull=False)
    serializer_class = PortSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = PortSerializer(data=request.data)
        if serializer.is_valid():
            try:
                if request.data.get('handler', None):
                    if str(serializer.validated_data['handler'].filename).endswith(".py"):
                        pid = start_port(serializer.validated_data['number'], serializer.validated_data['protocol'], serializer.validated_data['ssl'], serializer.validated_data['handler'])
                else:
                    pid = start_port(serializer.validated_data['number'], serializer.validated_data['protocol'], serializer.validated_data['ssl'])
                serializer.validated_data['pid'] = pid
                serializer.save()
            except Exception as e:
                logger.info("Failed to start port {}/{}".format(process.number, process.protocol))
                logger.error(e)
                return Response(serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PortDetail(generics.DestroyAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Port.objects.filter(pid__isnull=False)
    serializer_class = PortSerializer
    
    def delete(self, request, pk, *args, **kwargs):
        try:
            port = Port.objects.get(pk=int(pk))
            kill_process(port.pid)
        except Port.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return self.destroy(request, *args, **kwargs)

class SecretList(generics.ListAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Secret.objects.all()
    serializer_class = SecretSerializer
    paginate_by = 100
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = SecretFilter
    
class HandlerList(generics.ListAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Handler.objects.all()
    serializer_class = HandlerSerializer
    
class HandlerDetail(generics.UpdateAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Handler.objects.all()
    lookup_field = 'pk'
    http_method_names = ['get', 'patch'] #ignore put
    serializer_class = HandlerSerializer

    def patch(self, request, pk, *args, **kwargs):
        try:
            #not sure why partial_update wouldnt save
            instance = self.get_object()
            serializer = self.get_serializer(instance, data=request.data)
            if serializer.is_valid(raise_exception=True):
                settings = serializer.validated_data['settings']
                logger.debug("Validating settings")
                parser = CatcherConfigParser(SETTINGS.DEFAULT_HANDLER_SETTINGS)
                parser.read(settings)
                if parser.is_valid():
                    self.perform_update(serializer)
                else:
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                handler = self.get_object()
                ports = Port.objects.filter(handler=handler)
                for p in ports:
                    kill_process(p.pid)
                    pid = start_port(p.number, p.protocol, p.ssl, handler)
                    p.pid = pid
                    p.save()
            return Response(serializer.data)
        except Handler.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
class BlacklistList(generics.ListCreateAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    queryset = Blacklist.objects.all()
    serializer_class = BlacklistSerializer
    
class BlacklistDetail(generics.DestroyAPIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    serializer_class = BlacklistSerializer
    queryset = Blacklist.objects.all()
    lookup_field = 'pk'

class StatusView(APIView):
    authentication_classes = (BasicAuthentication,)
    permission_classes = (IsAuthenticated,)
    
    def get(self, request, format=None):
        data = {}
        try:
            data['fingerprint_count'] = Fingerprint.objects.all().count()
            data['handler_count'] = Handler.objects.all().count()
            data['port_count'] = Port.objects.all().count()
            data['callback_count'] = Callback.objects.all().count()
            data['secret_count'] = Secret.objects.all().count()
            data['domain'] = SETTINGS.DOMAIN
            data['clientip'] = get_client_ip(request)
            
            fingercallbacks = {}
            count = 0
            for f in Fingerprint.objects.all():
                fcount = Callback.objects.filter(fingerprint=f).count()
                if fcount > 0:
                    fingercallbacks[f.name] = fcount
                    count = count + fcount
            fingercallbacks['other'] = Callback.objects.all().count() - count
            data['fingerprint_callback_count'] = fingercallbacks
            
            return Response(data, status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return JsonResponse(data)