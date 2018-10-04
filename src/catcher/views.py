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
from catcher.models import Port, Callback, Handler, Secret
from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR

import socket
import logging
from . import settings
import base64

logger = logging.getLogger(__name__)

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


