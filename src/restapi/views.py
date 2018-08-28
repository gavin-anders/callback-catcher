from rest_framework.views import APIView
from rest_framework import status, generics
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from catcher.models import Handler, Callback, Fingerprint, Port, Secret, Handler, Token
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework import authentication
from .serializers import CallbackSerializer, FingerprintSerializer
from .serializers import PortSerializer, SecretSerializer, HandlerSerializer, TokenSerializer
from django.shortcuts import get_object_or_404
from django.http import JsonResponse
from rest_framework import exceptions
from rest_framework import permissions

from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR
from catcher import settings
from catcher.utils import kill_process

import logging
import base64
from rest_framework.decorators import permission_classes

logger = logging.getLogger(__name__)

class StaticAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if not auth:
                return None
            try:
                if len(auth) == 2:
                    if auth[0].lower() == "basic":
                        user, passwd = base64.b64decode(auth[1]).split(':')
                        if user == settings.USERNAME and passwd == settings.PASSWORD:
                            user, created = User.objects.get_or_create(username=settings.USERNAME, email='fake@dummy.com')
                        else:
                            raise exceptions.AuthenticationFailed('Failed to authenticate')
            except:
                raise exceptions.AuthenticationFailed('Failed to authenticate')
            return (user, None)
        raise exceptions.AuthenticationFailed('Failed to authenticate')

class HandlerList(generics.ListAPIView):
    queryset = Handler.objects.all()
    serializer_class = HandlerSerializer
    authentication_classes = (StaticAuthentication,)

class CallbackList(generics.ListAPIView):
    queryset = Callback.objects.all()
    serializer_class = CallbackSerializer
    authentication_classes = (StaticAuthentication,)

class PortList(generics.ListCreateAPIView):
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    authentication_classes = (StaticAuthentication,)
    
    def post(self, request, *args, **kwargs):
        serializer = PortSerializer(data=request.data)
        if serializer.is_valid():
            try:
                if serializer.validated_data.get('pid', None) != None:
                    kill_process(pid)
                    logger.info("Killed process {}".format(pid))
                
                process = Service(LISTEN_IP, 
                          serializer.validated_data['number'], 
                          serializer.validated_data['protocol'], 
                          serializer.validated_data['ssl']
                          )
                if len(serializer.validated_data['handler'].filename) > 0:
                    process.set_handler(serializer.validated_data['handler'].filename)
                process.start()
                serializer.validated_data['pid'] = process.pid
                serializer.save()
                logger.info("Started process on pid {}".format(process.pid))
            except Exception as e:
                logger.error(e)
                return Response(serializer.errors, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class PortDetail(generics.DestroyAPIView):
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    authentication_classes = (StaticAuthentication,)
    
    def delete(self, request, pk, *args, **kwargs):
        try:
            port = Port.objects.get(pk=int(pk))
            kill_process(port.pid)
            logger.info("Killed process {}".format(port.pid))
        except Port.DoesNotExist:
            return Response(status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(e)
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return self.destroy(request, *args, **kwargs)

class CallbackSecretList(generics.ListAPIView):
    serializer_class = SecretSerializer
    authentication_classes = (StaticAuthentication,)
    
    def get_queryset(self):
        callbackid = self.kwargs['callbackid']
        try:
            callback = Callback.objects.get(pk=callbackid)
        except Callback.DoesNotExist:
            raise Http404
        return Secret.objects.filter(callback=callback)

class TokenList(generics.ListCreateAPIView):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer
    authentication_classes = (StaticAuthentication,)

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

class StatusView(APIView):
    authentication_classes = (StaticAuthentication,)
    
    def get(self, request, format=None):
        data = {}
        try:
            data['fingerprint_count'] = Fingerprint.objects.all().count()
            data['handler_count'] = Handler.objects.all().count()
            data['port_count'] = Port.objects.all().count()
            data['callback_count'] = Callback.objects.all().count()
            data['domain'] = settings.DOMAIN
            data['clientip'] = get_client_ip(request)
            return Response(data, status=status.HTTP_200_OK)
        except:
            return Response(status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        return JsonResponse(data)