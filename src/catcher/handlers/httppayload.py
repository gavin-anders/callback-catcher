import os
import logging
import magic
import re
import base64
from .basehandler import TcpHandler
import catcher.settings as SETTINGS

logger = logging.getLogger(__name__)

class httppayload(TcpHandler):
    NAME = "HTTP Payload"
    DESCRIPTION = '''A HTTP server that responds a response from the payload() function.'''
    SETTINGS = {
        'headers' : ({'header': 'Server', 'value': 'CallBackCatcher'}, ),
    }
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.req_headers = []
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.set_fingerprint('payload')
        data = self.handle_plaintext_request()
        
        if not data:
            return
            
        # Set the headers
        self.parse_headers(data)
        
        try:
            verb, path = self.parse_verb(data)
            getattr(self, verb)(path)
        except:
            self._400()
            raise
        
    def add_header(self, name, value):
        for h in self.headers:
            if h['header'] == name.lower():
                self.debug("Replacing header value for: {}".format(name))
                h['value'] = value
                return
        self.headers.append({'header':name, 'value':value})

    def parse_headers(self, data):
        '''
        sets the headers in use
        '''
        raw = data.splitlines()
        raw.pop(0) #remove verb
        for h in raw:
            if ":" in h:
                x = h.split(":", 2)
                self.req_headers.append({"header": x[0], "value": x[1]})
        
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
            
    def build_response(self, content=None):
        '''
        Build response with headers and content detection
        '''
        response = b'HTTP/1.1 200 OK\r\n'
        
        if content is not None:
            content_type = magic.from_buffer(content, mime=True)
            logger.debug("Autodetect type '{}'".format(content_type))
            print(content_type)
            self.add_header("content-type", content_type)
        
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            response = response + header.encode()
        
        response = response + b"Connection: Close\r\n"
        response = response + b"\r\n"
        if content:
            response = response + content.encode()
        return response
        
    def _404(self):
        content = b'HTTP/1.1 404 Not Found\r\n'
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            content = content + header.encode()
        content = content + b"Connection: Close\n\n"
        self.send_response(content)
        
    def _400(self):
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
        content = ""
        try:
            print("trying regex")
            m = re.search(r"\/payload\/(\d+)", path)
            if m.group():
                content = self.payload(int(m.group(1)))
            else:
                content = self.payload()
        except Exception as e:
            #print(e)
            pass

        if content:
            resp = self.build_response(content)
            self.send_response(resp)
        else:
            self._404()
        
    def _POST(self, path):
        self._GET(path)
            
        
    def payload(self, index=None):
        """
        Generates a payload
        """
        resp = ""
        payloadfilepath = '/tmp/payload.txt'
        try:
            #overwrite if the header is set
            for h in self.req_headers:
                if h['header'].lower() == "payload":
                    index = h['value']
                    break

            with open(payloadfilepath, 'r') as f:
                resp = f.readlines()[int(index)]
        except:
            self.debug("Failed to load payload or index")
        
        return resp
