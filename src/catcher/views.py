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
from catcher.forms import PortForm
from catcher.models import Port, Callback, Handler, Secret, Token
from catcher.service import Service
from catcher.settings import LISTEN_IP, HANDLER_DIR

import socket
import logging
from . import settings
import base64

logger = logging.getLogger(__name__)

def basic_auth_login(view):
    def wrap(request, *args, **kwargs):
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2:
                if auth[0].lower() == "basic":
                    user, passwd = base64.b64decode(auth[1]).split(':')
                    if user == settings.USERNAME and passwd == settings.PASSWORD:
                        return view(request, *args, **kwargs)
        
        response = HttpResponse()
        response.status_code = 401
        response['WWW-Authenticate'] = 'Basic realm="CallbackCatcher"'
        return response
    wrap.__doc__ = view.__doc__
    wrap.__name__ = view.__name__
    return wrap

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

@method_decorator(basic_auth_login, name='dispatch') 
class PortView(ListView, ModelFormMixin):
    model = Port
    queryset = Port.objects.all().order_by('number')
    template_name = "ports.html"
    paginate_by = 21
    context_object_name = 'ports'
    form_class = PortForm
    
    def get_context_data(self, **kwargs):
        self.object = None
        context = super(PortView, self).get_context_data(**kwargs)
        context['handlers'] = Handler.objects.all()
        return context
            
    def post(self, request, *args, **kwargs):
        form = PortForm(request.POST)
        if form.is_valid():
            try:
                process = Service(LISTEN_IP, 
                                  form.validated_data['number'], 
                                  form.validated_data['protocol'], 
                                  form.validated_data['ssl']
                                  )
                if len(form.validated_data['handler'].filename) > 0:
                    process.set_handler(form.validated_data['handler'].filename)
                process.start()
                form.validated_data['pid'] = process.pid
                form.save()
                logger.info("Started process on pid {}".format(process.pid))
            except Exception as e:
                logger.error(e)
                return HttpResponse(status=500)
            return render(request, template_name)

@method_decorator(basic_auth_login, name='dispatch')    
class CallbackView(ListView):
    model = Callback
    queryset = Callback.objects.all().order_by('-timestamp')
    template_name = "callbacks.html"
    paginate_by = 21
    context_object_name = 'callbacks'
    
@method_decorator(basic_auth_login, name='dispatch')    
class SecretView(ListView):
    model = Secret
    queryset = Secret.objects.all()
    template_name = "secrets.html"
    paginate_by = 21
    context_object_name = 'secrets'
    
@method_decorator(basic_auth_login, name='dispatch')    
class TokenView(ListView):
    model = Token
    queryset = Token.objects.all()
    template_name = "tokens.html"
    paginate_by = 21
    context_object_name = 'tokens'

