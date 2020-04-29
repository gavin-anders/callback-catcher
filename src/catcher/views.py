from django.shortcuts import render
from catcher.settings import CATCHER_VERSION

def index(request):
    """
    Index route
    """
    context = {'version': CATCHER_VERSION}
    template = "index.html"
    return render(request, template, context)

def script(request):
    """
    Script route
    """
    template = "script.js"
    return render(request, template, content_type="application/javascript")


