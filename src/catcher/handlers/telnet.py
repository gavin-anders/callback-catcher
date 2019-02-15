'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

class telnet(TcpHandler):
    NAME = "Telnet"
    DESCRIPTION = '''Handles incoming telnet sessions. This handler only supports the "cooked" per-line mode, 
    not the binary version of the protocol'''
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.banner = b'OpenBSD/i386 (oof) (ttyp1)\r\n'
        self.welcome = b'\r\nLast login: Thu Dec  2 21:32:59 on ttyp1 from bam.zing.org\r\nWarning: no Kerberos tickets issued.\rOpenBSD 2.6-beta (OOF) #4: Tue Oct 12 20:42:32 CDT 1999\r\nWelcome to OpenBSD: The proactively secure Unix-like operating system.\r\n\r\n'
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        try:
            self.send_response(self.banner)
            self.send_response(b'Username: ')
            data = self.handle_raw_request()
            if len(data) > 0:
                while self.session is True:
                    self.set_fingerprint()
                    username = self.handle_request().decode('utf-8')
                    self.add_secret("Telnet Username", username.strip())
                    if len(username.strip()) > 0:
                        self.send_response(b'Password: ')
                        password = self.handle_request()
                        self.add_secret("Telnet Password", password.strip())
                        if len(password.strip()) > 0:
                            self.send_response(self.welcome)
                            termsess = True
                            while termsess is True:
                                self.send_response(b'$')
                                cmd = self.handle_request()
                                if cmd[:2] == '\xFF\xF4' or 'exit' in cmd.decode("utf-8") or 'quit' in cmd.decode("utf-8"):
                                    termsess = False
                            self.session = False
                    else:
                        self.session = False
        except:
            raise
        return