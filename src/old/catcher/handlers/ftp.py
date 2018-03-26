'''
Created on 15 Sep 2017

@author: gavin
'''

from basehandler import TcpHandler

class ftp(TcpHandler):
    '''
    Handles incoming FTPD connections
    '''
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_response(b'220 (CallbackCatcherFTPD 0.1a)\r\n')
        
        while self.session is True:
            data = self.handle_one_request()
            if data:
                command, param = self._parse_command(data)
                try:
                    if param:
                        getattr(self, command)(param)
                    else:
                        getattr(self, command)()                except Exception, e:
                    self.session = False
            else:
                self.session = False
    
    def _parse_command(self, line):
        '''
        returns the command that has been requested
        '''
        line = line.decode('utf-8').rstrip()
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
        self.send_response(b'257 "/callback/catcher"\r\n')
    
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
        self.send_response(b'230 You are now logged in.\r\n')
        self.add_secret("FTP Password", line.strip())
    
    def _USER(self, line):
        self.send_response(b'331 Please specify password.\r\n')
        #self.add_secret("FTP User", line.strip())
    
    def _QUIT(self):
        self.send_response(b'221-Goodbye.\r\n')
        self.session = False