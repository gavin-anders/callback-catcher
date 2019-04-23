'''
Created on 11 Oct 2017

@author: gavin
'''
from .basehandler import TcpHandler

import socket
import ssl
import re
import logging

logger = logging.getLogger(__name__)

class forwardsocket(TcpHandler):
    NAME = "Foward Socket"
    DESCRIPTION = '''Handles incoming connections and forwards onto a socket of your choice
    For use when callback catcher doesnt have an appropriate handler. This is not a socks4/5 proxy.
    '''
    CONFIG = {
        'forwardhost': 'www.westpoint.ltd.uk',
        'forwardport': 443,
        'clientbuffersize': 1024,
        'clienttimeout': 10,
        'sslforwarding': True,
        'httpforwarding': True
    }
    
    def __init__(self, *args):
        self.clientbuffer = [b'']
        TcpHandler.__init__(self, *args)
        
    def handle_timeout(self):
        logger.info("Timeout before finishing to read the client buffer. Sending what we have...")
        self.send_response(b''.join(self.clientbuffer))
        return super(TcpHandler, self).handle_timeout()
        
    def base_handle(self):
        #Connect to client and open socket
        clientsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsock.settimeout(self.clienttimeout)
        try:
            if self.is_ssl() is True and self.sslforwarding is True:
                context = ssl.SSLContext()
                context.verify_mode = ssl.CERT_NONE
                clientsock = context.wrap_socket(clientsock, 
                                             server_side=False, 
                                             do_handshake_on_connect=True, 
                                             suppress_ragged_eofs=True)
                self.debug("Client socket wrapped in SSL")
            host = socket.gethostbyname(self.forwardhost)
            clientsock.connect((host, self.forwardport))
            self.debug("Client socket opened to {}:{}".format(host, self.forwardport))
        except ssl.SSLError as e:
            self.debug("Problem wrapping client socket in SSL {}".format(str(e)))
            return
        except Exception as e:
            self.debug("Unable to connect to {}:{}".format(self.forwardhost, self.forwardport))
            return 
            
        data = self.handle_request()
        if len(data) > 0:
            if self.httpforwarding is True:
                try:
                    raw = data.decode('utf-8')
                    req = raw.splitlines()
                    reqline = req.pop(0).split(" ")
                    if len(reqline) == 3: #probably a HTTP/1.x
                        [command, path, version] = reqline
                        if version == "HTTP/1.1":   #only support HTTP/1.1
                            self.debug("Found HTTP/1.1 request")
                            matches = re.search(r"Host:\s(.*$)", raw, flags=re.MULTILINE|re.IGNORECASE)
                            if matches:
                                org = matches.group(0)
                                newhost = 'Host: {}:{}\r'.format(self.forwardhost, self.forwardport)
                                data = str.encode(raw.replace(org, newhost))
                                self.debug("Replaced '{}' with '{}'".format(org.strip(), newhost.strip()))
                except:
                    pass
            
            try:
                clientsock.send(data)
                self.debug("Client socket: Waiting for data")
                self.clientbuffer = [b'',]
                contentlength = None
                while True:
                    part = clientsock.recv(self.clientbuffersize)
                    self.clientbuffer.append(part)
                    self.debug("Client socket: Received {} bytes".format(len(part)))
                    if self.httpforwarding is True:
                        if contentlength is None:
                            #read the content length
                            try:
                                part = part.decode('utf-8')
                                matches = re.search(r"Content-Length:\s(.*)$", part, flags=re.MULTILINE|re.IGNORECASE)
                                if matches:
                                    contentlength = int(matches.group(1))
                            except:
                                pass
                        elif len(b''.join(self.clientbuffer)) > contentlength:
                            self.debug("Client socket: Buffer now longer than content length. Stopping")
                            break
                    elif len(part) == 0: #no more data to receive
                        break
                self.send_response(b''.join(self.clientbuffer))
                self.debug("Relaying data from {}:{} to {}:{}".format(self.forwardhost, self.forwardport, self.client_address[0], self.client_address[1]))
            except Exception as e:
                if "timeout" in str(e):
                    self.error("Client socket: Connection to {}:{} timed out".format(self.forwardhost, self.forwardport))
                else:
                    raise
        self.debug("Client socket closed")
        clientsock.close()
                