'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

class pop3(TcpHandler):
    NAME = "POP3"
    DESCRIPTION = '''POP3 mail server. Records username and password to secrets.'''

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.username = None
        self.password = None
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.request.send(b'+OK pop ready for requests from %s\r\n' % self.client_address[0])
        
        while self.session is True:
            data = self.handle_one_request()         
            if len(data) > 0:
                line = data.decode('utf-8').rstrip()
                command, param = self._parse_command(line)
                try:
                    command = '_' + command
                    if param:
                        getattr(self, command)(param)
                    getattr(self, command)()
                except Exception as e:
                    #print e
                    pass
            else:
                break
        
        #Print out the creds for now
        print("#####################################")
        if self.username:
            print("[+] POP3 USERNAME: %s" % self.username)
        if self.password:
            print("[+] POP3 PASSWORD: %s" % self.password)
        print("#####################################")
        return
        
    def _parse_command(self, line):
        '''
        returns the command that has been requested
        '''
        line = line.decode('utf-8').rstrip()
        param = ''
        try:
            parsed = line.split(' ')
            command = parsed[0]
            command = command.replace(" ", "_")
            param = parsed[1]
        except:
            pass
        return (command, param)
        
    def _USER(self, username):
        self.username = username
        self.request.send(b'+OK send PASS\r\n')
        
    def _PASS(self, password):
        self.request.send(b'+OK Welcome.\r\n')
        self.password = password
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
        self.request.send(b'+Ok\r\n')
        
    def _QUIT(self):
        self.request.send(b'DONE\r\n')
        self.session = False
        
    def default(self):
        self.request.send(b'Not implemented\r\n')