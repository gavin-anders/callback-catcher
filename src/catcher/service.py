import multiprocessing
import os
import importlib
import ssl
import threading
import socket
import sys
import logging
import inspect

from catcher.models import Port, Blacklist

from socketserver import TCPServer
from socketserver import UDPServer
from socketserver import ThreadingMixIn
from .handlers import basehandler
from .config import CatcherConfigParser
from .catcherexceptions import *

import catcher.settings as settings

logger = logging.getLogger(__name__)

def block_ip(ip):
    BLACKLIST = list(Blacklist.objects.values_list('ip', flat=True))
    if ip in BLACKLIST:
        logger.debug("Blocked IP {}".format(ip))
        return False
    return True

def set_socket_type():
    family = socket.AF_INET
    if settings.IPV6:
        family = socket.AF_INET6
    return family

class ThreadedTCPServer(ThreadingMixIn, TCPServer):
    daemon_threads = True
    allow_reuse_address = True
    address_family = set_socket_type()
    
    def verify_request(self, request, client_address):
        return block_ip(client_address[0])
    
class ThreadedUDPServer(ThreadingMixIn, UDPServer):
    daemon_threads = True
    allow_reuse_address = True
    max_packet_size = 2048
    address_family = set_socket_type()
    
    def verify_request(self, request, client_address):
        return block_ip(client_address[0])
    
#####################################

class Service(multiprocessing.Process):
    '''
    Represents a single port
    logging is likely not to work
    '''
    def __init__(self, ip, port, protocol, ssl, ipv6=False):
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
    
    def _set_socket_type(self):
        if self.ipv6 is True:
            self.address_family = socket.AF_INET6
        else:
            self.address_family = socket.AF_INET6
            
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
        
    def set_ssl_context(self, certfile, keyfile):
        '''
        Sets the ssl key and cert for the port
        '''
        self.sslcert = certfile
        self.sslkey = keyfile
        
    def set_handler(self, handlerfile):
        '''
        Sets the local handler file
        '''
        handlername = os.path.splitext(os.path.basename(handlerfile))[0]
        try:
            plugin = importlib.import_module('catcher.handlers.' + handlername)
            self.handler = getattr(plugin, handlername)
            logger.debug("Set custom handler: '{}'".format(handlerfile))
        except ImportError:
            logger.error("Importing file from local handlers directory failed. Using default handler...")
            self.handler = None
            
    def set_config(self, config):
        '''
        Config is a dictionary
        Set local attributes as well as the CONFIG variable
        '''
        if self.handler:
            #set the CONFIG variable
            setattr(self.handler, 'CONFIG', config)
            
            #set dynamic attributes
            for i, v in config.items():
                config_name = str(i)
                try:
                    setattr(self.handler, config_name, v)
                    logger.debug("{}.{}={}".format(self.handler.__name__, config_name, repr(v)))
                except AttributeError:
                    raise
        else:
            logger.debug("Handler configuration settings not set")
            
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
                if self.handler:
                    #start server with specific handler
                    if self.protocol == 'udp':
                        server = ThreadedUDPServer(address, self.handler)
                    else:
                        server = ThreadedTCPServer(address, self.handler)
                else:
                    #start server with standard handlers
                    if self.protocol == 'udp':
                        server = ThreadedUDPServer(address, basehandler.UdpHandler)
                    else:
                        server = ThreadedTCPServer(address, basehandler.TcpHandler)
    
                if self.ssl_enabled() is True:
                    server.socket = ssl.wrap_socket(server.socket, 
                                                    certfile=self.sslcert, 
                                                    keyfile=self.sslkey, 
                                                    server_side=True)
                    server.is_ssl = True
                else:
                    server.is_ssl = False
                    
                logger.info("Starting service on {}/{}".format(self.number, self.protocol))
                thread = threading.Thread(target=server.serve_forever())
                thread.start()
            except Exception as e:
                #dont raise anything here as we cant catch in the main thread
                #use utils.is_process_running() to detect if pid is live
                logger.error("Failed to start service on {}/{}".format(self.number, self.protocol))
                logger.debug("Error: {}".format(e))
                self.shutdown()
                

                