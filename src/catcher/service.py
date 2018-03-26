import multiprocessing
import os
import importlib
import ssl
import threading
import socket
import sys

from SocketServer import TCPServer
from SocketServer import UDPServer
from SocketServer import ThreadingMixIn
from handlers import basehandler

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
        self.port = port
        self.protocol = protocol.lower()
        self.ssl = ssl
        self.ipv6 = ipv6
        self.sslcert = None
        self.sslkey = None
        self.daemon = True
        self.handler = None
        
    def __str__(self):
        return "%s://%s:%i" % (self.protocol, self.ip, self.port)
    
    def shutdown(self):
        self.log.info("Terminating %i" % self.pid)
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
        
    def set_handler(self, handlerfile, handlerdir=None):
        '''
        Sets the local handler file
        '''
        handlername = os.path.splitext(os.path.basename(handlerfile))[0]
        print handlername
        try:
            plugin = importlib.import_module('catcher.handlers.' + handlername)
            self.handler = getattr(plugin, handlername)
            print "Using custom handler: '%s'" % handlerfile
        except ImportError:
            #Doesnt quite work in daemon mode
            try:
                sys.path.append(handlerdir)
                plugin = importlib.import_module('handlers.' + handlername)
                self.handler = getattr(plugin, handlername)
                print "Using custom handler: '%s'" % os.path.join(handlerdir, handlerfile)
            except:
                print "import from local handlers failed using default"
                self.handler = None

    def run(self):
        '''
        Starts the port as a service
        '''
        while not self.exit.is_set():          
            #Do we need ipv6? - this is a bit shit as it will be either ipv4 or ipv6
            try:
                address = (self.ip, self.port)
                if self.ipv6:
                    address = ('::1', self.port, 0, 0)
                
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
                #Pass variables to handlers
                thread = threading.Thread(target=server.serve_forever())
                #thread.daemon = True
                print "Starting service on: %s %i/%s" % (address, self.protocol)
                thread.start()
            except Exception, e:
                print e
                self.shutdown()
                
if __name__ == "__main__":
    process = Service('127.0.0.1', 1234, 'tcp', 0, logger)
    process.set_handler('ftp.py', '/opt/catcher/handler')
    process.start()
    process.join()
    print process.pid

    
    
