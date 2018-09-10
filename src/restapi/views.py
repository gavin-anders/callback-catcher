from django.contrib.auth.models import User
from django.shortcuts import get_object_or_404
from django.http import JsonResponse

from rest_framework import status, generics, authentication, exceptions, permissions
from rest_framework.response import Response
from rest_framework.authentication import BasicAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import permission_classes
from rest_framework.views import APIView

from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR
from catcher.utils import kill_process
from catcher import settings
from catcher.models import Handler, Callback, Fingerprint, Port, Secret, Handler, Token

from .serializers import CallbackSerializer
from .serializers import PortSerializer, SecretSerializer, HandlerSerializer, TokenSerializer

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

class CallbackList(generics.ListAPIView):
    queryset = Callback.objects.all()
    serializer_class = CallbackSerializer
    paginate_by = 100
    #authentication_classes = (BasicAuthentication,)
    
class CallbackDetail(generics.RetrieveAPIView):
    queryset = Callback.objects.all()
    serializer_class = CallbackSerializer
    lookup_field = 'id'
    #authentication_classes = (BasicAuthentication,)

class PortList(generics.ListCreateAPIView):
    queryset = Port.objects.all()
    serializer_class = PortSerializer
    #authentication_classes = (BasicAuthentication,)
    
    def put(self, request, *args, **kwargs):
        serializer = PortSerializer(data=request.data)
        if serializer.is_valid():
            try:
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
    #queryset = Port.objects.all()
    queryset = Port.objects.filter(pid__isnull=False)
    serializer_class = PortSerializer
    #authentication_classes = (BasicAuthentication,)
    
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

class SecretList(generics.ListAPIView):
    queryset = Secret.objects.all()
    serializer_class = SecretSerializer
    paginate_by = 100
    #authentication_classes = (BasicAuthentication,)
    
class SecretDetail(generics.RetrieveAPIView):
    queryset = Secret.objects.all()
    serializer_class = SecretSerializer
    lookup_field = 'id'
    #authentication_classes = (BasicAuthentication,)
    
class HandlerList(generics.ListAPIView):
    queryset = Handler.objects.all()
    serializer_class = HandlerSerializer
    #authentication_classes = (BasicAuthentication,)

class TokenList(generics.ListCreateAPIView):
    queryset = Token.objects.all()
    serializer_class = TokenSerializer
    #authentication_classes = (BasicAuthentication,)

class StatusView(APIView):
    #authentication_classes = (BasicAuthentication,)
    
    def get(self, request, format=None):
        data = {}
        try:
            data['fingerprint_count'] = Fingerprint.objects.all().count()
            data['handler_count'] = Handler.objects.all().count()
            data['port_count'] = Port.objects.all().count()
            data['callback_count'] = Callback.objects.all().count()
            data['secret_count'] = Secret.objects.all().count()
            data['domain'] = settings.DOMAIN
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