'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

class pop3(TcpHandler):
    NAME = "POP3"
    DESCRIPTION = '''POP3 mail server. Records username and password to secrets.'''
    SETTINGS = {
        'banner': '220 (CallbackCatcherFTPD 0.1a)\r\n',
    }

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.username = None
        self.password = None
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_response('+OK pop ready for requests from {}\r\n'.format(self.client_address[0]), encoding='utf-8')
        
        while self.session is True:
            data = self.handle_plaintext_request()
            if data:
                command, param = self._parse_command(data)
                try:
                    if param:
                        getattr(self, command)(param)
                    else:
                        getattr(self, command)()
                except Exception as e:
                    self.session = False
            else:
                self.session = False
        
    def _parse_command(self, line):
        '''
        returns the command that has been requested
        '''
        line = line.strip()
        param = ''
        try:
            parsed = line.split(' ')
            if len(parsed) > 1:
                command = parsed[0]
                param = parsed[1]
            else:
                command = line
                param = None
        except:
            pass
        return ("_"+command, param)
    
    def _USER(self, username):
        self.username = username
        self.add_secret("POP Username", username)
        self.send_response(b'+OK send PASS\r\n')
        
    def _PASS(self, password):
        self.send_response(b'+OK Welcome.\r\n')
        self.add_secret("POP Password", password)
        self._QUIT()
        
    def _STAT(self, param):
        self.default()
        
    def _LIST(self, param):
        self.default()
        
    def _RETR(self, param):
        self.default()
        
    def _DELE(self, param):
        self.default()
        
    def _RSET(self, param):
        self.default()
        
    def _NOOP(self, param):
        self.send_response(b'+Ok\r\n')
        
    def _QUIT(self):
        self.send_response(b'DONE\r\n')
        self.session = False
        
    def default(self):
        self.send_response(b'Not implemented\r\n')