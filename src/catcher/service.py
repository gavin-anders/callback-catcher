import multiprocessing
import os
import importlib
import ssl
import threading
import socket
import sys
import logging
import inspect

from catcher.models import Port

from socketserver import TCPServer
from socketserver import UDPServer
from socketserver import ThreadingMixIn
from .handlers import basehandler
from .config import CatcherConfigParser

import catcher.settings as settings

logger = logging.getLogger(__name__)

##### OUR MIXINS HERE ############
class ThreadedIPv6TCPServer(ThreadingMixIn, TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET6
    
class ThreadedIPv6UDPServer(ThreadingMixIn, UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = socket.AF_INET6
    max_packet_size = 2048

class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    
class ThreadedUDPServer(ThreadingMixIn, UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 2048
    
#####################################

class Service(multiprocessing.Process):
    '''
    Represents a single port
    logging is likely not to work
    '''
    def __init__(self, ip, port, protocol, ssl, ipv6=0):
        multiprocessing.Process.__init__(self)
        self.exit = multiprocessing.Event()
        self.ip = ip
        self.number = port
        self.protocol = protocol.lower()
        self.ssl = ssl
        self.ipv6 = ipv6
        self.sslcert = None
        self.sslkey = None
        self.daemon = True
        self.handler = None

    def __str__(self):
        return "%s://%s:%i" % (self.protocol, self.ip, self.number)
    
    def shutdown(self):
        logger.info("Terminating {}".format(self.pid))
        self.exit.set()
    
    def ssl_enabled(self):
        '''
        Returns true/false if ssl is enabled
        '''
        if self.ssl is 1:
            return True
        else:
            return False
        
    def ipv6_enabled(self):
        '''
        Returns true/false if set to run as ipv6
        '''
        if self.ipv6 is 1:
            return True
        else:
            return False
        
    def set_ssl_context(self, certfile, keyfile):
        '''
        Sets the ssl key and cert for the port
        '''
        self.sslcert = certfile
        self.sslkey = keyfile
        
    def set_handler(self, handlerfile, config_string=None):
        '''
        Sets the local handler file
        '''
        handlername = os.path.splitext(os.path.basename(handlerfile))[0]
        try:
            plugin = importlib.import_module('catcher.handlers.' + handlername)
            self.handler = getattr(plugin, handlername)
            logger.info("Set custom handler: '{}'".format(handlerfile))
            
            config = CatcherConfigParser(defaults=settings.DEFAULT_HANDLER_SETTINGS)
            if config_string:
                config.read(config_string)
            self.handler = self._set_config(self.handler, config.get_settings())  
        except ImportError:
            logger.error("Importing file from local handlers directory failed. Using default handler...")
            self.handler = None
            
    def _set_config(self, handler, setting):
        for i, v in setting.items():
            setting_name = i
            try:
                setattr(handler, setting_name, v)
                logger.debug("{}.{}={}".format(handler.__name__, setting_name, repr(v)))
            except AttributeError:
                pass
        return handler
            
    def is_running(self):
        '''
        Checks if the service is running
        '''
        if isinstance(self.pid, int):
            return True
        else:
            return False

    def run(self):
        '''
        Starts the port as a service
        '''
        while not self.exit.is_set():
            #Do we need ipv6? - this is a bit shit as it will be either ipv4 or ipv6
            try:
                address = (self.ip, self.number)
                if self.ipv6:
                    address = ('::1', self.number, 0, 0)
                
                if self.handler:
                    #start server with specific handler
                    if self.protocol == 'udp' and self.ipv6 is True:
                        server = ThreadedIPv6UDPServer(address, self.handler)
                    elif self.protocol == 'tcp' and self.ipv6 is True:
                        server = ThreadedIPv6TCPServer(address, self.handler)
                    elif self.protocol == 'udp':
                        server = ThreadedUDPServer(address, self.handler)
                    else:
                        server = ThreadedTCPServer(address, self.handler)
                else:
                    #start server with standard handlers
                    if self.protocol == 'udp' and self.ipv6 is True:
                        server = ThreadedIPv6UDPServer(address, basehandler.UdpHandler)
                    elif self.protocol == 'tcp' and self.ipv6 is True:
                        server = ThreadedIPv6TCPServer(address, basehandler.TcpHandler)
                    elif self.protocol == 'udp':
                        server = ThreadedUDPServer(address, basehandler.UdpHandler)
                    else:
                        server = ThreadedTCPServer(address, basehandler.TcpHandler)
                        
                if self.ssl_enabled() is True:
                    server.socket = ssl.wrap_socket(server.socket, 
                                                    certfile=self.sslcert, 
                                                    keyfile=self.sslkey, 
                                                    server_side=True)
                logger.info("Starting service on {}/{}".format(self.number, self.protocol))
                thread = threading.Thread(target=server.serve_forever())
                thread.start()
            except Exception as e:
                logger.error("Failed to start service on {}/{}".format(self.number, self.protocol))
                self.shutdown()
                   
    
