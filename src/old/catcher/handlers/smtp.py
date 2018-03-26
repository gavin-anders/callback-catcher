'''
Created on 15 Sep 2017

@author: gavin
'''

from basehandler import TcpHandler
import ssl
import os

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
        self.request.send(b'220 %s ESMTP CallbackCatcher service ready\r\n' % self.HOSTNAME)
        
        while self.session is True:
            data = self.handle_one_request()         
            if len(data) > 0:
                line = data.decode('utf-8').rstrip()
                try:
                    if line.startswith('HELO'):
                        self._HELO(line.replace('HELO', '').strip())
                    elif line.startswith('EHLO'):
                        self._EHLO(line.replace('EHLO', '').strip())
                    elif line.startswith('STARTTLS'):
                        self._STARTTLS()
                    elif line.startswith('MAIL FROM'):
                        self._MAIL_FROM(line.replace('MAIL_FROM:', '').strip())
                    elif line.startswith('RCPT TO'):
                        self._RCPT_TO(line.replace('RECPT_TO:', '').strip())
                    elif line.startswith('DATA'):
                        self._DATA(line.replace('DATA', '').strip())
                    elif line.startswith('QUIT'):
                        self._QUIT()
                except Exception, e:
                    print e
            else:
                break
        return
        
    def _HELO(self, param=None):
        if param:
            self.request.send(b'220 Hello %s, pleased to meet you\r\n') % param
        else:
            self.request.send(b'220 Hello, pleased to meet you\r\n') % param
        
    def _EHLO(self, param=None):
        if param:
            self.request.send(b'250 Hello %s\r\n250 STARTTLS\r\n' % param)
        else:
            self.request.send(b'250 Hello\r\n250 STARTTLS\r\n' % param)
        
    def _STARTTLS(self):
        self.request.send(b'220 Ready to start TLS\r\n')
        key = os.path.join(os.getcwd(), 'ssl', 'server.key')
        cert = os.path.join(os.getcwd(), 'ssl', 'server.crt')
        
        self.request = ssl.wrap_socket(self.request, keyfile=key, certfile=cert, server_side=True)
        
    def _MAIL_FROM(self, param=None):
        self.request.send(b'250 Okd\r\n')
        if param:
            line = param.replace('MAIL_FROM:', '').strip()
        else:
            self.request.send(b'Not implemented\r\n')
            self._QUIT()
        
    def _RCPT_TO(self, param=None):
        self.request.send(b'250 Okd\r\n')
        if param:
            line = param.replace('RCPT_TO:', '').strip()
        else:
            self.request.send(b'Not implemented\r\n')
            self._QUIT()
        
    def _DATA(self, param=None):
        self.request.send(b'354 Send datad\r\n')
        
    def _QUIT(self):
        self.request.send(b'Bye\r\n')
        self.session = False