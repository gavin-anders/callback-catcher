'''
Created on 11 Oct 2017

@author: gavin
'''
from .basehandler import TcpHandler

import socket

class forwardsocket(TcpHandler):
    NAME = "Foward Socket"
    DESCRIPTION = '''Handles incoming connections and forwards onto a socket of your choice
    For use when callback catcher doesnt have an appropirate handler. This is not a socks4/5 proxy.
    '''
    SETTINGS = {
        'forwardhost': '127.0.0.1',
        'forwardhport': 4444,
        'buffersize': 4096
    }
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        #Connect to client and open socket
        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsock.settimeout(self.timeout)
        try:
            clientsock.connect((self.forwardhost, self.forwardport))
        except Exception as e:
            return
             
        while self.session == True:
            data = self.handle_raw_request()
            if len(data) > 0:
                try:
                    clientsock.send(data)
                    buffer = ""
                    while True:
                        clientdata = clientsock.recv(self.buffersize)
                        if not clientdata:
                            break
                        buffer += clientdata
                    self.request.send(buffer)
                    self.session = False
                except Exception as e:
                    if "timeout" in str(e):
                        raise
                    else:
                        self.session = False
        clientsock.close()
            