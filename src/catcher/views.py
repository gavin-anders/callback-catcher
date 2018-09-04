from django.shortcuts import render, redirect
from django.views import generic
from django.views.generic.edit import ModelFormMixin
from django.views.generic import ListView, DeleteView
from django.views.decorators.cache import never_cache
from django.contrib.auth import authenticate, login, logout
from django.utils.http import is_safe_url
from django.utils.decorators import method_decorator
from django.http import HttpResponse, HttpResponseRedirect
from django.contrib.auth.models import User
from catcher.models import Port, Callback, Handler, Secret, Token
from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR

import socket
import logging
from . import settings
import base64

logger = logging.getLogger(__name__)

def check_ports():
    ports = Port.objects.all()
    for p in ports:
        server_address = (settings.LISTEN_IP, p.number)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if p.protocol == 'udp':
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.bind(server_address)
            logger.info("Removing {} entry from DB".format(p))
            p.delete()
        except:
            pass
        finally:
            sock.close()

def index(request):
    """
    Index route
    """
    context = {'version': settings.CATCHER_VERSION}
    template = "index.html"
    return render(request, template, context)

def script(request):
    """
    Script route
    """
    template = "script.js"
    return render(request, template)


