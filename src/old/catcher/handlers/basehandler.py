'''
Created on 24 Aug 2017

@author: gavin

'''
from SocketServer import BaseRequestHandler
from datetime import datetime
from ssl import SSLError
from ..datastructures import Callback, Secret
from ..communicator import Communicator

import socket
import logging

logger = logging.getLogger('catcher')

class TcpHandler(BaseRequestHandler):
    '''
    Listener for raw TCP socket
    '''
    SERVER_PROTOCOL = 'TCP'
    TIMEOUT = 10
    BUFFER_SIZE = 1024
    
    ######### BASE HANDLER FUNCTIONS ###########
   
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.callback = None
        BaseRequestHandler.__init__(self, *args)
        
    def setup(self):
        print "setup()"
        self.callback = Callback(
                    self.client_address,
                    self.server.server_address,
                    self.SERVER_PROTOCOL,
                    "",
                    self.server.CONFIG.identifier)
        self.request.settimeout(TcpHandler.TIMEOUT)
        
    def handle(self):
        '''
        Dont overwrite this is needed for basic handling
        '''
        print "handle()"
        try:
            self.base_handle()
        except socket.timeout:
            self.handle_timeout()
        except SSLError as e:
            #SSLError: The read operation timed out
            print e
        except Exception as e:
            if 'The read operation timed out' in e.args:
                self.handle_timeout()
            elif 'Connection reset by peer' in e.args:
                logger.error(e.args)
            else:
                raise
        
    def finish(self):
        '''
        Finish up function
        Log the callback to the main server 
        '''
        print "finish()"
        logger.debug("Sending callback details back to the server")
        comm = Communicator(self.server.CONFIG.serverurl)
        comm.authenticate(self.server.CONFIG.serveruser, self.server.CONFIG.serverpass)
        comm.send_callback(self.callback.__dict__)
        logger.debug("Callback sent")

        
    def handle_error(self):
        '''
        Dont do anything for now
        '''
        self.request.close()
        
    def handle_timeout(self):
        pass
    
    ########## CUSTOM FUNCTIONS ##############
    
    def base_handle(self):
        '''
        Overwrite this method for subclasses
        This just does a basic response
        '''
        print "base_handle()"
        self.send_response(b'CallBackCatcher online\r\n')
        ignore = self.handle_one_request()    #dont do anything with it by default
        
    def handle_one_request(self):
        '''
        Handles the next incoming request in the buffer
        Used by subclasses
        '''
        print "handle_one_request()"
        packet = self.request.recv(self.BUFFER_SIZE)
        if packet is not None:
            self.callback.append_packet(packet)
            return packet
        
    def send_response(self, response):
        '''
        Use this to send the response back down the socket
        Used by subclasses
        '''
        self.callback.append_packet(response)
        self.request.send(response)
        
    def add_secret(self, name, value):
        '''
        Use this to add a secret to the callback
        Used by subclasses
        '''
        print "[+] Secret (%s): %s" % (name, value)
        logger.info("Secret logged")
        secret = Secret(name, value)
        self.callback.append_secret(secret.__dict__)
        
class UdpHandler(BaseRequestHandler):
    '''
    Listener for raw UDP socket
    '''
    SERVER_PROTOCOL = 'UDP'
    TIMEOUT = 30
    BUFFER_SIZE = 2048
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.callback = None
        self.client_socket = None
        BaseRequestHandler.__init__(self, *args)
        
    def setup(self):
        #its UDP dont set a timeout
        print "udp.setup()"
        self.callback = Callback(
                    self.client_address,
                    self.server.server_address,
                    self.SERVER_PROTOCOL,
                    "",
                    self.server.CONFIG.identifier)
        
    def handle(self):
        print "udp.handle()"
        try:
            self.base_handle()
        except socket.timeout:
            self.handle_timeout()
        except SSLError as e:
            #SSLError: The read operation timed out
            print "SSL Error"
        except Exception as e:
            if 'The read operation timed out' in e.args:
                self.handle_timeout()
            elif 'Connection reset by peer' in e.args:
                print "Client closed the connection"
            else:
                raise
        
    def finish(self):
        '''
        finish up function
        '''
        print "udp.finish()"
                    
    def handle_error(self):
        print "udp.handle_error()"
        self.request.close()
        
        ########## CUSTOM FUNCTIONS ##############
    
    def base_handle(self):
        '''
        Overwrite this method for subclasses
        This just does a basic response
        '''
        print "udp.base_handle()"
        ignore = self.handle_one_request()    #dont do anything with it by default
        
    def handle_one_request(self):
        '''
        Handles the next incoming request in the buffer
        Used by subclasses
        '''
        print "handle_one_request()"
        self.client_socket = self.request[1]
        packet = self.request[0].rstrip()
        if packet is not None:
            self.callback.append_packet(packet)
            return packet
        
    def send_response(self, response):
        '''
        Use this to send the response back down the socket
        Used by subclasses
        '''
        print "udp.send_response()"
        self.callback.append_packet(response)
        self.client_socket.sendto(response, self.client_address)
        
    def add_secret(self, name, value):
        '''
        Use this to add a secret to the callback
        Used by subclasses
        '''
        print "udp.add_secret()"
        print "[+] Secret (%s): %s" % (name, value)
        secret = Secret(name, value)
        self.callback.append_secret(secret.__dict__)
