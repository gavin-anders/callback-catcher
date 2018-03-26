'''
Created on 11 Oct 2017

@author: gavin
'''
from basehandler import TcpHandler

import socket

class forwardsock(TcpHandler):
    '''
    Handles incoming connections and forwards onto a socket of your choice
    For use when callback catcher doesnt have an appropirate handler
    '''

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.forwardhost = '127.0.0.1'
        self.forwardport = 666
        self.timeout = 5
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        #Connect to client and open socket
        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsock.settimeout(self.timeout)
        try:
            clientsock.connect((self.forwardhost, self.forwardport))
        except Exception, e:
            print e
            return
             
        while self.session == True:
            data = self.handle_one_request()
            if len(data) > 0:
                try:
                    clientsock.send(data)
                    buffer = ""
                    while True:
                        clientdata = clientsock.recv(4096)
                        if not clientdata:
                            break
                        buffer += clientdata
                    self.request.send(buffer)
                    self.session = False
                except Exception as e:
                    if "timeout" in str(e):
                        raise
                    else:
                        print "ForwardSock: " + str(e)
                        self.session = False
        clientsock.close()
            