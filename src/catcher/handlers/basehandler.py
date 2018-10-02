'''
Created on 24 Aug 2017

@author: gavin

'''
from socketserver import BaseRequestHandler
from datetime import datetime
from ssl import SSLError
from catcher.models import Callback, Secret, Fingerprint

import socket
import base64
import logging
import inspect

logger = logging.getLogger(__name__)

class BaseCatcherHandler(BaseRequestHandler):
    '''
    Our base handler that extends BaseRequestHandler and add extra functionality
    '''
    SERVER_PROTOCOL = ''
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.callback = None
        BaseRequestHandler.__init__(self, *args)
        
    ######### BASE HANDLER FUNCTIONS ###########
        
    def setup(self):
        logger.debug("setup()")
        self.callback = Callback.create(
                            self.client_address[0],
                            self.client_address[1],
                            self.server.server_address[0],
                            self.server.server_address[1],
                            self.SERVER_PROTOCOL,
                            bytearray())
        logger.info("Connection to {}/{} from {}:{} established".format(self.server.server_address[1], self.SERVER_PROTOCOL, self.client_address[0], self.client_address[1]))
        
    def finish(self):
        '''
        Finish up function taken from BaseRequestHandler
        '''
        logger.debug("finish()")
        logger.info("Connection to {}/{} from {}:{} closed".format(self.server.server_address[1], self.SERVER_PROTOCOL, self.client_address[0], self.client_address[1]))
        
    def handle_error(self):
        '''
        Handle error function taken from BaseRequestHandler
        '''
        self.request.close()
        
    def handle_timeout(self):
        '''
        Handle timeout by client taken from BaseRequestHandler
        UDP wont hit this
        '''
        logger.info("Connection from {}:{} timed out".format(self.client_address[0], self.client_address[1]))
        
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
            logger.error("SSL Error - {}".format(str(e)))
        except Exception as e:
            if 'The read operation timed out' in e.args:
                self.handle_timeout()
            elif 'Connection reset by peer' in e.args:
                logger.debug(e.args)
            else:
                raise
        
    ######### CUSTOM FUNCTIONS ###########
     
    def base_handle(self):
        '''
        Overwrite this method for subclasses
        This just does a basic response
        '''
        logger.debug("base_handle()")
        pass    #dont do anything with it by default
        
    def set_timeout(self, timeout):
        '''
        Use this for TCP connections when a custom timeout is needed
        Set the timeout for the service
        '''
        self.request.settimeout(timeout)
        
    def set_fingerprint(self, name=None):
        '''
        For setting the fingerprint manually from within the handler
        Might overwrite detect_fingerprint in signals.py
        '''
        if self.callback.fingerprint is None:
            if name is None:
                name = str(self.__class__.__name__)
            f, c = Fingerprint.objects.get_or_create(name=name, defaults={'name':name, 'probe': ''})
            logger.info("Request recognised as '{}'".format(f.name))
            self.callback.fingerprint = f
            self.callback.save()
        return
        
    def debug(self, l):
        '''
        This is to be used by handlers needing to log to stout
        '''
        stack = inspect.stack()
        cls = stack[1][0].f_locals["self"].__class__
        meth = stack[1][0].f_code.co_name
        logger.debug("{}.<method '{}'>: {}".format(cls, meth, l))
        
    def add_secret(self, name, value):
        '''
        Use this to add a secret to the callback
        '''
        try:
            if isinstance(value, (bytes, bytearray)):
                #convert it to string if it is bytes
                value = value.decode()
            logger.info("Secret ({}): {}".format(name, value))
            if len(value) > 0:
                secret = Secret.objects.create(name=name, value=value, callback=self.callback)
        except Exception as e:
            logger.error("Failed to save secret {}".format(e))
        
    def append_data(self, data):
        '''
        Use this to append data to the callback object
        Acts as a buffer for the session
        '''
        if data is None:
            return
        
        if isinstance(data, str):  #check if we are working with a string
            data = str.encode(data) #convert to byte array
            
        self.callback.data = self.callback.data + data
        self.callback.datasize = len(self.callback.data)
        self.callback.save()

class TcpHandler(BaseCatcherHandler):
    '''
    Listener for raw TCP socket
    '''
    SERVER_PROTOCOL = 'TCP'
    TIMEOUT = 10
    BUFFER_SIZE = 1024
   
    def __init__(self, *args):
        '''
        TCP Constructor
        '''
        BaseCatcherHandler.__init__(self, *args)
        
    def setup(self):
        super().setup()
        self.set_timeout(self.TIMEOUT)
    
    def base_handle(self):
        '''
        Overwrite this method for subclasses
        This just does a basic response for the current class
        '''
        super().base_handle()
        self.send_response(b'CallBackCatcher (TcpHandler) online\r\n')
        ignore = self.handle_raw_request()    #dont do anything with it by default
        
    ########## CUSTOM FUNCTIONS ##############
        
    def handle_raw_request(self):
        '''
        Handles the next incoming raw request in the buffer
        Used by subclasses
        returns buffer in bytes
        '''
        logger.debug("handle_raw_request()")
        packet = self.request.recv(self.BUFFER_SIZE)
        if packet is not None:
            self.debug(packet)  
            self.append_data(packet)
            return packet
        
    def handle_plaintext_request(self):
        '''
        Handles the next incoming request as plain text
        Used by subclasses
        returns string
        '''
        return self.handle_raw_request().decode('utf-8')
        
    def send_response(self, response, encoding=None):
        '''
        Use this to send the response back down the socket
        Used by subclasses
        '''
        try:
            if encoding is not None:
                response = response.encode(encoding)
            self.append_data(response)
            self.debug(response)
            self.request.send(response)
        except LookupError as e:
            logger.warning("{}. Sending default response".format(str(e)))
            self.request.send(b'\r\n')
        except TypeError as e:
            logger.warning("{}. Sending default response".format(str(e)))
                
class UdpHandler(BaseCatcherHandler):
    '''
    Listener for raw UDP socket
    '''
    SERVER_PROTOCOL = 'UDP'
    TIMEOUT = 30
    BUFFER_SIZE = 2048
    
    def __init__(self, *args):
        '''
        UDP Constructor
        '''
        self.client_socket = None
        BaseCatcherHandler.__init__(self, *args)
        
     ########## CUSTOM FUNCTIONS ##############
    
    def base_handle(self):
        super().base_handle()
        self.send_response(b'CallBackCatcher (UdpHandler) online\r\n')
        ignore = self.handle_raw_request()    #dont do anything with it by default
        
    def handle_raw_request(self):
        '''
        Handles the next incoming request in the buffer
        Used by subclasses
        '''
        logger.debug("handle_raw_request()")
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
        
