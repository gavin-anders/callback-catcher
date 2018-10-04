'''
Created on 03 Oct 2018

@author: gavin
'''
from .basehandler import TcpHandler
from catcher.settings import SSL_KEY, SSL_CERT

import socket
import re
import logging
import ssl
from urllib import parse as urlparse

logger = logging.getLogger(__name__)

class httpproxy(TcpHandler):
    NAME = "HTTP Proxy"
    DESCRIPTION = '''A HTTP proxy accepting the CONNECT method.'''
    SETTINGS = {
            'timeout': 5
        }
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        data = self.handle_plaintext_request()
        
        if not data:
            return
        
        try:
            auth = re.search(r"Proxy-Authorization:\s(\w+)\s(.*)\r", data)
            if auth:
                if "Basic" in auth.group(1):
                    creds = base64.b64decode(auth.group(2)).decode().split(":")
                    self.add_secret('Basic Username', creds[0])
                    self.add_secret('Basic Password', creds[1])
                elif "Bearer" in auth.group(1):
                    creds = base64.b64decode(auth.group(2)).decode()
                    self.add_secret('Bearer Token', creds)
        except Exception as e:
            logger.error("Problem reading creds: {}".format(e))
            
        try:
            reqline, content = data.split('\r', 1)
            verb, path, ver = reqline.strip().split(' ', 2)
            if verb == "CONNECT":
                self.connect(data)
            else:
                print("Got non CONNECT method")
                address = self.read_address(path)
                r = re.search(r"http(s)?:\/\/[^\/]*(.*)", path)
                if r:
                    path = r.group(2)
                reqline = '{} {} {}'.format(verb, path, ver)
                request = reqline + content
                clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                clientsock.settimeout(self.timeout)
                clientsock.connect(address)
                clientsock.send_all(request.encode())
                buffer = b""
                while True:
                    clientdata = clientsock.recv(1024)
                    if not clientdata:
                        break
                    buffer = buffer + clientdata
                self.send_response(buffer)
        except Exception as e:
            logger.error("Unable to connect to client")
            self.send_response(b'HTTP/1.1 400 Bad Request\r\nConnection: Close\r\n\r\n')
            raise
        
    def connect(self, data):
        line, content = data.split('\n', 1)
        verb, path, ver = line.split(' ')
        hostheader = None
        h = re.search(r"Host:\s(.*)\r", data)
        if h:
            logger.debug("Using Host header: {}".format(h.group(1)))
            hostheader = h.group(1)
        address = self.read_address(path, hostheader)
        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsock.settimeout(5)
        try:
            #try initial connection
            clientsock.connect(address)
            logger.debug("Sending back status 200")
            self.send_response(b"HTTP/1.0 200 Connection established\r\n\r\n")
        except Exception as e:
            logger.debug("Connection failed. Sending back status 504. {}".format(str(e)))
            self.send_response(b"HTTP/1.1 504 Gateway Timeout\r\n")
            return
        finally:
            clientsock.close()
            
        try:
            self.request = ssl.wrap_socket(self.request, keyfile=SSL_KEY, certfile=SSL_CERT, server_side=True)
            logger.info("Wrapped HTTP connection in SSL/TLS")
            self.setup()
            data = self.handle_plaintext_request()
            self.debug(data)
            
            context = ssl._create_unverified_context()
            clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            clientsock.settimeout(self.timeout)
            clientsock = context.wrap_socket(clientsock, server_hostname=address[0])
            clientsock.connect(address)
            clientsock.send(data.encode())
            
            buffer = b""
            while True:
                clientdata = clientsock.recv(1024)
                if not clientdata:
                    break
                buffer = buffer + clientdata
            self.send_response(buffer)
            
        except ssl.SSLError as e:
            logger.error("Wrapping SSL Error: {}".format(e))
        except socket.timeout:
            logger.error("Forwarding to client timed out")
        finally:
            self.request.close()
        
    def read_address(self, reqline, hostheader=''):
        '''
        Should return the host and port for the destination host.
        If possible these values are derived from absolute URI.
        If absolute URI is not available then host header is used.
        '''
        if reqline.startswith('/'):
            #This is a non absolute URI
            if ':' in hostheader:
                host, port = host.split(':')
                port = int(port)
            else:
                if self.is_ssl():
                    port = 443
                else:
                    port = 80
        else:
            host = ''
            port = 443
            uri = reqline.strip()
            if not uri.startswith('http'):
                uri = 'http://{}/'.format(uri)
            host = urlparse.urlparse(uri).hostname
            if uri.startswith('http://'):
                port = 80
            elif uri.startswith('https://'):
                port = 443
            if urlparse.urlparse(uri).port:
                port = int(urlparse.urlparse(uri).port)
        self.debug("Parsed {}:{}".format(host, port))
        return (host, port)
            