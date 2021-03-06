'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import TcpHandler

class ftp(TcpHandler):
    NAME = "FTP"
    DESCRIPTION = '''Handles incoming FTPD connections. Records username and password to secrets.'''
    CONFIG = {
        'banner': '220 (CallbackCatcherFTPD 0.1a)\r\n',
    }
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
    
    def base_handle(self):
        self.send_response(self.get_config_value('banner'), 'utf-8')
        
        while self.session is True:
            data = self.handle_request().decode('utf-8')
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
                
    def _CWD(self, line):
        pass
    
    def _PORT(self, line):
        pass
        
    def _ASCII(self, line):
        pass
        
    def _PWD(self, line):
        self.set_fingerprint()
        self.send_response('257 "/callback/catcher"\r\n', 'utf-8')
    
    def _DELE(self, line):
        pass
    
    def _HELP(self, line):
        pass
    
    def _HOST(self, line):
        pass
    
    def _LIST(self, line):
        pass
    
    def _RETR(self, line):
        pass
    
    def _STOR(self, line):
        pass
    
    def _PASS(self, line):
        self.add_secret("FTP Password", line)
        self.send_response('230 You are now logged in.\r\n', 'utf-8')
    
    def _USER(self, line):
        self.set_fingerprint()
        self.add_secret("FTP Username", line)
        self.send_response('331 Please specify password.\r\n', 'utf-8')
    
    def _QUIT(self):
        self.request.send('221-Goodbye.\r\n', 'utf-8')
        self.session = False
        #self.request.close() #this breaks stuff with threading
