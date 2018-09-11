'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

import ssl
import os
import base64

class smtp(TcpHandler):
    '''
    Handles incoming FTPD connections
    '''
    HOSTNAME = 'catcher.nccgroup.com'

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_response(b'220 catcher ESMTP CallbackCatcher service ready\r\n')
        
        while self.session is True:
            data = self.handle_plaintext_request()       
            if len(data) > 0:
                line = data.rstrip()
                try:
                    if line.startswith('HELO'):
                        self._HELO(line.replace('HELO', '').strip())
                    elif line.startswith('EHLO'):
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
        key = os.path.join(os.getcwd(), 'ssl', 'server.key')
        cert = os.path.join(os.getcwd(), 'ssl', 'server.crt')
        self.request = ssl.wrap_socket(self.request, keyfile=key, certfile=cert, server_side=True)
        
    def _MAIL_FROM(self, param=""):
        self.send_response(b'250 Ok\r\n')
        
    def _RCPT_TO(self, param=None):
        self.send_response(b'250 Ok\r\n')
        
    def _DATA(self):
        while True:
            data = self.handle_plaintext_request()
            if data.strip() == ".":
                break
        self.send_response(b'250 Ok\r\n')
        
    def _AUTH_PLAIN(self, param=""):
        if param == "":
            self.send_response(b'334\r\n')
            param = self.handle_plaintext_request()
        
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
        username = self.handle_plaintext_request()
        self.add_secret("SMTP Username", base64.b64decode(username.strip()))
        self.send_response(b'334 UGFzc3dvcmQ6\r\n')
        password = self.handle_plaintext_request()
        self.add_secret("SMTP Password", base64.b64decode(password.strip()))
        self.send_response(b'235 Authentication successful\r\n')
        
    def _QUIT(self):
        self.send_response(b'221 Bye\r\n')
        self.session = False
