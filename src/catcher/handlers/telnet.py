'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

class telnet(TcpHandler):
    '''
    Handles incoming telnet connections
    A telnet session in "cooked" (per-line) mode.
    Tested with Linux telnet client
    '''
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.banner = '''OpenBSD/i386 (oof) (ttyp1)\r\n'''
        self.welcome = '''\r\nLast login: Thu Dec  2 21:32:59 on ttyp1 from bam.zing.org\r\nWarning: no Kerberos tickets issued.\rOpenBSD 2.6-beta (OOF) #4: Tue Oct 12 20:42:32 CDT 1999\r\nWelcome to OpenBSD: The proactively secure Unix-like operating system.\r\n\r\n '''
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.request.send(self.banner)
        
        username = ''
        password = ''
        
        self.request.send(b'Username: ')
        data = self.handle_one_request()
        if len(data) > 0:
            if data[0] == '\xFF':
                print("Telnet command incoming")
                while True:
                    username = self.handle_one_request().rstrip()
                    if len(username) > 0:
                        self.request.send(b'Password: ')
                        password = self.handle_one_request().rstrip()
                        if len(password) > 0:
                            self.request.send(self.welcome)
                            #Keep reading shit until ^C
                            termsess = True
                            while termsess is True:
                                self.request.send(b'$')
                                cmd = self.handle_one_request()
                                if cmd[:2] == '\xFF\xF4' or 'exit' in cmd or 'quit' in cmd:
                                    termsess = False
                            break
                    else:
                        break
                    
        if username is not '':
            print("#####################################")
            print('USERNAME:\t%s' % username.rstrip())
        if password is not '':    
            print('PASSWORD:\t%s' % password.rstrip())
        print("#####################################")
        return