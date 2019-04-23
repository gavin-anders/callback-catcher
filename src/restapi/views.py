from django.contrib.auth.models import User, Group, Permission
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from django import forms

from rest_framework import status, generics, authentication, exceptions, permissions
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated, IsAdminUser, DjangoModelPermissions
from rest_framework.decorators import permission_classes
from rest_framework.views import APIView
from rest_framework.mixins import DestroyModelMixin, ListModelMixin
from rest_framework.authtoken.views import ObtainAuthToken
from rest_framework.authtoken.models import Token as AuthToken
from rest_framework.exceptions import NotFound, PermissionDenied

from django_filters import rest_framework as filters

from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR, SSL_KEY, SSL_CERT, USERNAME
from catcher import settings as SETTINGS
from catcher.config import CatcherConfigParser
from catcher.catcherexceptions import *
from catcher.utils import *
from catcher.models import Handler, Callback, Fingerprint, Port, Secret, Handler, Blacklist, Token, Client

from .serializers import CallbackSerializer, CallbackDetailSerializer, ClientSerializer, PortSerializer, SecretSerializer, HandlerSerializer, BlacklistSerializer, TokenSerializer
from .authentications import ClientHeaderAuthentication
from .filters import CallbackFilter, SecretFilter
from .permissions import ClientUserPermissions

import logging
import base64
import json
import time

logger = logging.getLogger(__name__)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def start_port(number, protocol, ssl, handler, config_string):
    process = Service(LISTEN_IP, number, protocol, ssl, SETTINGS.IPV6)
    if handler:
        process.set_handler(handler.filename)
        parser = CatcherConfigParser()
        parser.read(config_string)
        process.set_config(parser.get_config())
    if ssl is 1:
        process.set_ssl_context(SSL_CERT, SSL_KEY)
    process.start()
    return process.pid

class CallbackList(generics.ListAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions,)
    queryset = Callback.objects.all().order_by('-pk')
    serializer_class = CallbackSerializer
    paginate_by = 100
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = CallbackFilter
    
class CallbackDetail(generics.RetrieveAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions,)
    queryset = Callback.objects.all()
    serializer_class = CallbackDetailSerializer
    
class PortList(generics.ListCreateAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    queryset = Port.objects.filter(pid__isnull=False)
    serializer_class = PortSerializer
    
    def post(self, request, *args, **kwargs):
        serializer = PortSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            try:
                if request.data.get('handler', None):
                    if str(serializer.validated_data['handler'].filename).endswith(".py"):
                        pid = start_port(serializer.validated_data['number'], serializer.validated_data['protocol'], serializer.validated_data['ssl'], serializer.validated_data['handler'], serializer.validated_data['config'])
                else:
                    pid = start_port(serializer.validated_data['number'], serializer.validated_data['protocol'], serializer.validated_data['ssl'])
                    
                time.sleep(1)   #hack time wait for process to error
                if is_process_running(pid) is True:
                    serializer.validated_data['pid'] = pid
                    serializer.save()
                    return Response(status=status.HTTP_201_CREATED)
                else:
                    logger.info("Failed to start port")
                    logger.error("Process thread exited early")
                    return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except MissingConfigSection:
                logger.info("Failed to start port")
                logger.error("Invalid config section")
                raise ValidationError("Invalid config section")
            except InvalidConfigFormat:
                logger.info("Failed to start port")
                logger.error("Invalid config format")
                raise ValidationError("Invalid config format")
            except Exception as e:
                logger.info("Failed to start port")
                logger.error(e)
                return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return Response(status=status.HTTP_400_BAD_REQUEST)

class PortDetail(generics.DestroyAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions,)
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
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    queryset = Secret.objects.all()
    serializer_class = SecretSerializer
    paginate_by = 100
    filter_backends = (filters.DjangoFilterBackend,)
    filterset_class = SecretFilter
    
class HandlerList(generics.ListAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    queryset = Handler.objects.all()
    serializer_class = HandlerSerializer
        
class BlacklistList(generics.ListCreateAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    queryset = Blacklist.objects.all()
    serializer_class = BlacklistSerializer
    
class BlacklistDetail(generics.DestroyAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    serializer_class = BlacklistSerializer
    queryset = Blacklist.objects.all()
    lookup_field = 'pk'

class StatusView(APIView):
    #authentication_classes = (BasicAuthentication,)
    #permission_classes = (IsAuthenticated,)
    
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
    
class SettingsView(APIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, IsAdminUser, )
    
    def post(self, request, *args, **kwargs):
        try:
            if 'action' in request.data:
                action = request.data['action']
                if action == 'clear_callbacks':
                    logger.info("Clearing Callback table")
                    Callback.objects.all().delete()
                    Secret.objects.all().delete()
                elif action == 'clear_secret':
                    logger.info("Clearing Secret table")
                    Secret.objects.all().delete()
                elif action == 'stop_ports':
                    logger.debug("Stopping all ports")
                    for port in Port.objects.all():
                        kill_process(port.pid)
                elif action == 'clear_clients':
                    logger.debug("Clearing all clients")
                    Client.objects.all().exclude(username=SETTINGS.USERNAME).delete()
                else:
                    return Response(status=status.HTTP_404_NOT_FOUND)
        except:
            raise
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        else:
            return Response(status=status.HTTP_200_OK)
        
class TokenList(generics.ListCreateAPIView, DestroyModelMixin):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    serializer_class = TokenSerializer
    queryset = Token.objects.all()
    paginate_by = 100
    filter_backends = (filters.DjangoFilterBackend,)
    
    def get_queryset(self):
        if 'pk' in self.kwargs:
            if int(self.request.user.id) == int(self.kwargs.get('pk')) or self.request.user.username == USERNAME:
                client = Client.objects.get(pk=self.kwargs.get('pk'))
                queryset = Token.objects.filter(client=client).order_by('-pk') # raise 404 if
                return queryset
            raise PermissionDenied()
        return Client.objects.none()
    
    def delete(self, request, *args, **kwargs):
        try:
            client = Client.objects.get(pk=self.kwargs.get('pk'))
            if not client:
                return Response(status=status.HTTP_404_NOT_FOUND)
            Token.objects.filter(client=client).delete()
            return Response(status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
    def post(self, request, *args, **kwargs):
        if 'pk' in self.kwargs:
            if int(request.user.id) == int(self.kwargs.get('pk')) or request.user.username == USERNAME:
                serializer = TokenSerializer(data=request.data)
                client = Client.objects.get(pk=self.kwargs.get('pk'))
                if not client:
                    return Response(status=status.HTTP_404_NOT_FOUND)
                if serializer.is_valid(raise_exception=True):
                    serializer.validated_data['client'] = client
                    serializer.save()
                    return Response(data=serializer.data, status=status.HTTP_200_OK)
            raise PermissionDenied()
    
class ClientList(generics.ListCreateAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions, )
    serializer_class = ClientSerializer
    queryset = Client.objects.all()
    paginate_by = 100
    lookup_field = 'pk'
        
    def post(self, request, *args, **kwargs):
        ip = get_client_ip(request)
        agent = request.META['HTTP_USER_AGENT']
        serializer = ClientSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            serializer.validated_data['source'] = ip
            serializer.validated_data['agent'] = agent
            obj = serializer.save()
            obj.groups.add(Group.objects.get(name='clients'))   # add new user to the clientgroups
            return Response(data=serializer.data, status=status.HTTP_201_CREATED)
    
class ClientDetail(generics.RetrieveDestroyAPIView):
    authentication_classes = (BasicAuthentication, ClientHeaderAuthentication)
    permission_classes = (IsAuthenticated, ClientUserPermissions,  )
    serializer_class = ClientSerializer
    queryset = Client.objects.all()
    lookup_field = 'pk'
    
    def delete(self, request, *args, **kwargs):
        try:
            client = Client.objects.get(pk=self.kwargs.get('pk'))
            if not client:
                return Response(status=status.HTTP_404_NOT_FOUND)
            client.exclude(username=SETTINGS.USERNAME)
            return Response(status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
