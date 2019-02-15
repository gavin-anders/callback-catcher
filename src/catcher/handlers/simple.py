'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

class simple(TcpHandler):
    NAME = "Simple"
    DESCRIPTION = '''The most basic of handlers. Echos any data that is sent. Use this as a template or example.'''
    SETTINGS = {
        'banner': 'Callback Catcher Online\r\n',
    }
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        """
        Simple echo handler
        """
        self.send_response(self.banner)
        
        while self.session is True:
            
            data = self.handle_request()
            if data:
                #MANIPULATE DATA HERE
                data = data
                
                #SEND DATA TO CLIENT
                self.send_response(data)