import os
import logging
import magic
import re
import base64
from .basehandler import TcpHandler
import catcher.settings as SETTINGS

logger = logging.getLogger(__name__)

class httpstatic(TcpHandler):
    NAME = "HTTP (static content)"
    DESCRIPTION = '''A HTTP server that responds with files and content from a local directory.'''
    SETTINGS = {
        'webroot'     : 'www/',
        'detect_type' : True,
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
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.set_fingerprint('http')
        data = self.handle_plaintext_request()
        
        if not data:
            return
        
        try:
            auth = re.search(r"Authorization:\s(\w+)\s(.*)\r", data)
            if "Basic" in auth.group(1):
                creds = base64.b64decode(auth.group(2)).decode().split(":")
                self.add_secret('Basic Username', creds[0])
                self.add_secret('Basic Password', creds[1])
            elif "Bearer" in auth.group(1):
                creds = base64.b64decode(auth.group(2)).decode()
                self.add_secret('Bearer Token', creds)
        except Exception as e:
            pass
        
        try:
            verb, path = self.parse_verb(data)
            getattr(self, verb)(path)
        except:
            self.send_400()
            raise
        
    def parse_verb(self, line):
        '''
        returns the verb that has been requested
        '''
        line = line.strip()
        param = ''
        parsed = line.split(' ')
        if len(parsed) > 2:
            verb = parsed[0]
            path = parsed[1]
        return ("_" + verb.upper(), path)
    
    def load_file(self, path):
        d = os.path.abspath(os.path.join(SETTINGS.HANDLER_CONTENT_DIR, self.webroot.lstrip("/")))
        p = os.path.normpath(os.path.join(d, path.lstrip("/")))
        if os.path.isfile(p):
            logger.debug("Loading file: {}".format(p))
            f = open(p, 'r')
            return f.read()
        elif os.path.isdir(p):
            #Load index
            p = os.path.join(p, 'index.html')
            logger.debug("Loading file: {}".format(p))
            try:
                f = open(p, 'r')
                return f.read()
            except:
                return None
        else:
            logger.debug("Loading file failed: {}".format(p))
            return None
            
    def build_response(self, content=None):
        '''
        Build response with headers and content detection
        '''
        response = b'HTTP/1.1 200 OK\r\n'
        if content is not None and self.detect_type is True:
            content_type = magic.from_buffer(content, mime=True)
            logger.debug("Autodetect type '{}'".format(content_type))
            h = {'header': 'Content-type', 'value': content_type}
            self.headers.append(h)
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            response = response + header.encode()
        response = response + b"Connection: Close\r\n"
        response = response + b"\r\n"
        if content:
            response = response + content.encode()
        return response
    
    def send_404(self):
        content = b'HTTP/1.1 404 Not Found\r\n'
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            content = content + header.encode()
        content = content + b"Connection: Close\n\n"
        self.send_response(content)
        
    def send_400(self):
        content = b'HTTP/1.1 400 Bad Request\r\n'
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            content = content + header.encode()
        content = content + b"Connection: Close\r\n\r\n"
        self.send_response(content)
            
    def _HEAD(self):
        resp = self.build_response()
        self.send_response(resp)
        
    def _GET(self, path):
        content = self.load_file(path)
        if content:
            resp = self.build_response(content)
            self.send_response(resp)
        else:
            self.send_404()
        
    def _POST(self, path):
        self._GET(path)
            
        
