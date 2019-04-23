'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import TcpHandler

class netbios(TcpHandler):
    NAME = "NetBIOS Session"
    DESCRIPTION = '''Responds to NetBIOS session requests. To be used along side SMB handler.'''
    CONFIG = {}
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        data = self.handle_request()
        if data[0] == "\x81":
            self.send_response(b"\x82\x00\x00\x00")