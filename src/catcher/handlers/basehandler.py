'''
Created on 24 Aug 2017

@author: gavin

'''
from socketserver import BaseRequestHandler
from datetime import datetime
from ssl import SSLError
from catcher.models import Callback, Secret

import socket
import base64
import logging

logger = logging.getLogger(__name__)

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
        logger.debug("setup()")
        self.callback = Callback.create(
                            self.client_address[0],
                            self.client_address[1],
                            self.server.server_address[0],
                            self.server.server_address[1],
                            self.SERVER_PROTOCOL,
                            "")
        logger.info("TCP Connection from {}:{}".format(self.client_address[0],self.client_address[1]))
        self.request.settimeout(TcpHandler.TIMEOUT)
        
    def handle(self):
        '''
        Dont overwrite this is needed for basic handling
        '''
        logger.debug("handle()")
        try:
            self.base_handle()
        except socket.timeout:
            self.handle_timeout()
        except SSLError as e:
            #SSLError: The read operation timed out
            print(e)
        except Exception as e:
            if 'The read operation timed out' in e.args:
                self.handle_timeout()
            elif 'Connection reset by peer' in e.args:
                print(e.args)
            else:
                raise
        
    def finish(self):
        '''
        Finish up function
        Log the callback to the main server 
        '''
        logger.debug("finish()")
        #Create secrets here
        
    def handle_error(self):
        '''
        Dont do anything for now
        '''
        self.request.close()
        
    def handle_timeout(self):
        logger.info("Connection from {}:{} timed out".format(self.client_address[0],self.client_address[1]))
    
    
    ########## CUSTOM FUNCTIONS ##############
    
    def base_handle(self):
        '''
        Overwrite this method for subclasses
        This just does a basic response
        '''
        logger.debug("base_handle()")
        self.send_response(b'CallBackCatcher online\r\n')
        ignore = self.handle_one_request()    #dont do anything with it by default
        
    def handle_one_request(self):
        '''
        Handles the next incoming request in the buffer
        Used by subclasses
        '''
        logger.debug("handle_one_request()")
        packet = self.request.recv(self.BUFFER_SIZE)
        if packet is not None:
            self.append_data(packet)
            return packet
        
    def send_response(self, response):
        '''
        Use this to send the response back down the socket
        Used by subclasses
        '''
        self.append_data(response)
        self.request.send(response)
        
    def add_secret(self, name, value):
        '''
        Use this to add a secret to the callback
        Used by subclasses
        '''
        try:
            logger.info("Secret (%s): %s" % (name, value))
            secret = Secret.objects.create(name=name, value=value, callback=self.callback)
        except Exception as e:
            logger.error("Failed to save secret {}".format(e))
        
    def append_data(self, data):
        '''
        Use this to add data to the callback
        '''
        newdata = base64.b64decode(self.callback.data) + data
        self.callback.data = base64.b64encode(newdata)
        self.callback.datasize = len(newdata)
        self.callback.save()
        
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
        logger.debug("udp.setup()")
        self.callback = Callback.create(
                            self.client_address[0],
                            self.client_address[1],
                            self.server.server_address[0],
                            self.server.server_address[1],
                            self.SERVER_PROTOCOL,
                            "")
        logger.info("UDP Connection from {}:{}".format(self.client_address[0],self.client_address[1]))
        
    def handle(self):
        logger.debug("udp.handle()")
        try:
            self.base_handle()
        except SSLError as e:
            #SSLError: The read operation timed out
            logger.debug("SSL Error")
        except Exception as e:
            if 'The read operation timed out' in e.args:
                self.handle_timeout()
            elif 'Connection reset by peer' in e.args:
                logger.error("Client closed the connection")
            else:
                logger.exception(e)
        
    def finish(self):
        '''
        finish up function
        '''
        logger.debug("udp.finish()")
                    
    def handle_error(self):
        logger.error("udp.handle_error()")
        self.request.close()
        
        ########## CUSTOM FUNCTIONS ##############
    
    def base_handle(self):
        '''
        Overwrite this method for subclasses
        This just does a basic response
        '''
        logger.debug("udp.base_handle()")
        ignore = self.handle_one_request()    #dont do anything with it by default
        
    def handle_one_request(self):
        '''
        Handles the next incoming request in the buffer
        Used by subclasses
        '''
        logger.debug("handle_one_request()")
        self.client_socket = self.request[1]
        packet = self.request[0].rstrip()
        if packet is not None:
            self.append_data(packet)
            return packet
        
    def send_response(self, response):
        '''
        Use this to send the response back down the socket
        Used by subclasses
        '''
        logger.debug("udp.send_response()")
        self.append_data(response)
        self.client_socket.sendto(response, self.client_address)
        
    def add_secret(self, name, value):
        '''
        Use this to add a secret to the callback
        Used by subclasses
        '''
        try:
            logger.info("Secret (%s): %s" % (name, value))
            secret = Secret.objects.create(name=name, value=value, callback=self.callback)
        except Exception as e:
            logger.error("Failed to save secret {}".format(e))
        
    def append_data(self, data):
        '''
        Use this to add data to the callback
        '''
        newdata = base64.b64decode(self.callback.data) + data
        self.callback.data = base64.b64encode(newdata)
        self.callback.datasize = len(newdata)
        self.callback.save()
