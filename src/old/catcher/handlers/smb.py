'''
Created on 15 Sep 2017

@author: gavin
'''

from basehandler import TcpHandler
from packets import *

class smb(TcpHandler):
    '''
    Handles incoming connections and keeps it open
    '''

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        #self.request.settimeout(0.5)
            
        data = self.handle_one_request()
            
        if len(data) == 0:
            return
        
        while self.session is True:
            if data[0] == "\x81":
                print "SMB session request"
                self.request.send('\x82\x00\x00\x00')
                data = self.handle_one_request()
                
            if data[8:10] == "\x72\x00":
                print "Negotiate proto answer"
                smbheader = ''
                
            if data[8:10] == "\x73\x00":
                print "Session Setup AndX Request"
                
            self.session = False
            
    def pidcalc(self, data):  #Set PID SMB Header field.
        pack=data[30:32]
        return pack
    
    def midcalc(self, data):  #Set MID SMB Header field.
        return data[34:36]