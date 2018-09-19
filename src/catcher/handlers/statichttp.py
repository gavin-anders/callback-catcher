'''
Created on 15 Sep 2017

@author: gavin
'''
import os
import logging
from .basehandler import TcpHandler

logger = logging.getLogger(__name__)

class statichttp(TcpHandler):
    NAME = "Static HTTP"
    DESCRIPTION = '''A HTTP server that responds with files and content from a local directory.'''
    SETTINGS = {
        'encoding': 'utf-8',
        'webroot': '/var/www/html/',
        'headers': (
            {'header': 'Server', 'value': 'CallBackCatcher'}, 
            {'header': 'Set-Cookie', 'value': 'hello12345'}, 
        ),
        'content': '<html><body>This is a page</body></html>',
        'resp': 'HTTP/1.1 200 OK'
    }
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.set_fingerprint('HTTP')
        data = self.handle_plaintext_request()
        path = data.splitlines()[0].split(" ")[1].split("?")[0]
        file = os.path.join(self.webroot, path)
        if os.path.isfile(file):
            logger.info("Serving {}".format(file))
            with open(filename) as f:
                self.content = f.read()
        r = self._build_response(self.resp, self.headers, self.content)
        self.send_response(r, encoding=self.encoding)
        
    def _build_response(self, resp, headers, content):
        '''
        Returns response for status 200
        '''
        response = self.resp + "\r\n"
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            response = response + header
        response = response + "Connection: Close\r\n"
        response = response + "\r\n"
        response = response + content 
        response = response + "\r\n"
        return response
        