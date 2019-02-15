import os
import logging
import magic
import re
import base64
from .basehandler import TcpHandler
from .basehttp import basehttp
import catcher.settings as SETTINGS

logger = logging.getLogger(__name__)

class httpbasic(basehttp):
    NAME = "HTTP Basic"
    DESCRIPTION = '''A HTTP server that responds with files and content from a local directory.'''
    SETTINGS = {
        'webroot'     : 'www/',
        'detect_type' : True,
        'dir_browsing': True,
        'headers'     : (
             {'header': 'Server', 'value': 'CallBackCatcher'}, 
             {'header': 'Set-Cookie', 'value': 'hello12345'}, 
        ),
    }
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.webroot = os.path.abspath(os.path.join(SETTINGS.HANDLER_CONTENT_DIR, self.webroot.lstrip("/")))
        basehttp.__init__(self, *args)
        
    def do_GET(self):
        #self.send_http_response(200, "Hello world")
        self.send_error(500)