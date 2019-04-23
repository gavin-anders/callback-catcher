'''
Created on 15 Sep 2017

@author: gavin

test STARTTLS with openssl s_client -connect 127.0.0.1:25 -starttls smtp
'''

from .basehandler import TcpHandler
from catcher.settings import SSL_KEY, SSL_CERT

import ssl
import os
import base64

class smtp(TcpHandler):
    NAME = "SMTP"
    DESCRIPTION = '''Another basic mail server. Records LOGIN AUTH and AUTH PLAIN to secrets.'''
    CONFIG = {
        'hostname': 'catcher.pentestlabs.co.uk',
    }

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_response('220 {} ESMTP CallbackCatcher service ready\r\n'.format(self.hostname), encoding='utf-8')
        
        while self.session is True:
            data = self.handle_request()       
            if len(data) > 0:
                line = data.rstrip()
                try:
                    if line.startswith('HELO'):
                        self.set_fingerprint()
                        self._HELO(line.replace('HELO', '').strip())
                    elif line.startswith('EHLO'):
                        self.set_fingerprint()
                        self._EHLO(line.replace('EHLO', '').strip())
                    elif line.startswith('STARTTLS'):
                        self._STARTTLS()
                    elif line.startswith('MAIL FROM'):
                        self._MAIL_FROM()
                    elif line.startswith('RCPT TO'):
                        self._RCPT_TO()
                    elif line.startswith('DATA'):
                        self._DATA()
                    elif line.startswith('AUTH PLAIN'):
                        self._AUTH_PLAIN(line.replace('AUTH PLAIN', '').strip())
                    elif line.startswith('AUTH LOGIN'):
                        self._AUTH_LOGIN()
                    elif line.startswith('QUIT'):
                        self._QUIT()
                except Exception as e:
                    raise
                    session = False
            else:
                break
        return
        
    def _HELO(self, param=""):
        resp = '220 Hello {} pleased to meet you\r\n'.format(param)
        self.send_response(resp.encode()) 
        
    def _EHLO(self, param=None):
        resp = '250 Hello {}\r\n250 STARTTLS\r\n'.format(param)
        self.send_response(resp.encode()) 
        
    def _STARTTLS(self):
        self.send_response(b'220 Ready to start TLS\r\n')
        self.request = ssl.wrap_socket(self.request, keyfile=SSL_KEY, certfile=SSL_CERT, server_side=True)
        
    def _MAIL_FROM(self, param=""):
        self.send_response(b'250 Ok\r\n')
        
    def _RCPT_TO(self, param=None):
        self.send_response(b'250 Ok\r\n')
        
    def _DATA(self):
        while True:
            data = self.handle_request()
            if data.strip() == ".":
                break
        self.send_response(b'250 Ok\r\n')
        
    def _AUTH_PLAIN(self, param=""):
        if param == "":
            self.send_response(b'334\r\n')
            param = self.handle_request()
        
        credsline = base64.b64decode(param)
        creds = credsline.split(b"\0")
        if len(creds) == 3:
            self.add_secret("SMTP Identity", creds[0])
            self.add_secret("SMTP Username", creds[1])
            self.add_secret("SMTP Password", creds[2])
        else:
            self.add_secret("SMTP Username", creds[0])
            self.add_secret("SMTP Password", creds[1])
        self.send_response(b'235 Authentication successful\r\n')
        
    def _AUTH_LOGIN(self):
        self.send_response(b'334 VXNlcm5hbWU6\r\n')
        username = self.handle_request()
        self.add_secret("SMTP Username", base64.b64decode(username.strip()))
        self.send_response(b'334 UGFzc3dvcmQ6\r\n')
        password = self.handle_request()
        self.add_secret("SMTP Password", base64.b64decode(password.strip()))
        self.send_response(b'235 Authentication successful\r\n')
        
    def _QUIT(self):
        self.send_response(b'221 Bye\r\n')
        self.session = False
