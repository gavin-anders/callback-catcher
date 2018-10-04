'''
Created on 03 Oct 2018

@author: gavin
'''
from .basehandler import TcpHandler

import socket
import re
import logging
from urllib import parse as urlparse

logger = logging.getLogger(__name__)

class httpproxy(TcpHandler):
    NAME = "HTTP Proxy"
    DESCRIPTION = '''A HTTP proxy accepting the CONNECT method.'''
    SETTINGS = {}
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.proxy_verbs = ('GET', 'POST', 'CONNECT', 'OPTIONS',)
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
            verb = self.parse_verb(data)
            getattr(self, verb)(data)
        except Exception as e:
            self.send_400()   
        
    def _CONNECT(self, data):
        line, content = data.split('\n', 1)
        verb, host, ver = line.split(' ')
        hostheader = None
        h = re.search(r"Host:\s(.*)\r", data)
        if h:
            hostheader = h.group(1)
        address = self.read_address(host, hostheader)
        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsock.settimeout(5)
        try:
            #try initial connection
            clientsock.connect(address)
            logger.debug("Sending back status 200")
            self.send_response(b"HTTP/1.1 200 OK\r\n")
            
        except Exception as e:
            logger.debug("Connection failed. Sending back status 504. {}".format(str(e)))
            self.send_response(b"HTTP/1.1 504 Gateway Timeout\r\n")
            return
        finally:
            clientsock.close()
            
    def send_400(self):
        content = b'HTTP/1.1 400 Bad Request\r\n'
        for h in self.headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            content = content + header.encode()
        content = content + b"Connection: Close\r\n\r\n"
        self.send_response(content)
            
    def parse_verb(self, line):
        '''
        returns the verb that has been requested
        '''
        line = line.strip()
        param = ''
        parsed = line.split(' ')
        if len(parsed) > 2:
            verb = parsed[0]
        return ("_" + verb.upper())
        
    def read_address(self, reqline, hostheader):
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
                port = 80
            #ADD CHECK TO SEE IF WE ARE ALREADY IN SSL TUNNEL
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
            