'''
Created on 15 Sep 2017

@author: gavin

https://www.pgcon.org/2014/schedule/attachments/330_postgres-for-the-wire.pdf


'''
import struct
import binascii
import os
import ssl

from .basehandler import TcpHandler

AUTH_REQ_OK="\x00\x00\x00\x00"    # User is authenticated  
AUTH_REQ_KRB4="\x00\x00\x00\x01"    # Kerberos V4. Not supported any more. 
AUTH_REQ_KRB5="\x00\x00\x00\x02"    # Kerberos V5. Not supported any more. 
AUTH_REQ_PASSWORD="\x00\x00\x00\x03"    # Password 
AUTH_REQ_CRYPT="\x00\x00\x00\x04"    # crypt password. Not supported any more. 
AUTH_REQ_MD5="\x00\x00\x00\x05"    # md5 password 
AUTH_REQ_SCM_CREDS="\x00\x00\x00\x06"    # transfer SCM credentials 
AUTH_REQ_GSS="\x00\x00\x00\x07"    # GSSAPI without wrap() 
AUTH_REQ_GSS_CONT="\x00\x00\x00\x08"    # Continue GSS exchanges 
AUTH_REQ_SSPI="\x00\x00\x00\x09"    # SSPI negotiate without wrap() 
AUTH_REQ_SASL="\x00\x00\x00\x10"    # Begin SASL authentication 
AUTH_REQ_SASL_CONT="\x00\x00\x00\x11"    # Continue SASL authentication 
AUTH_REQ_SASL_FIN="\x00\x00\x00\x12"    # Final SASL message 

class PostgresInitMessage(object):
    def __init__(self, data):
        self.length = data[:4]
        self.ssl = data[4:len(data)]
        
    def ssl_enabled(self):
        if self.ssl == "\x04\xD2\x16\x2F":
            return True
        return False
    
class PostgresStartup(object):
    def __init__(self, data):
        self.length = data[:4]
        self.protocol = data[4:8]
        parts = list(data[8:len(data)].split("\x00"))
        self.datapairs = dict(list(zip(parts[0::2], parts[1::2])))
        
class AuthenticationRequest(object):
    def __init__(self, type):
        self.cmd = "R"
        self.length = "\x00\x00\x00\x0c"
        self.authtype = type
        self.salt = "AAAA"
        
    def __str__(self):
        return self.cmd + self.length + self.authtype + self.salt
    
class AuthenticationResponse(object):
    def __init__(self, data):
        self.cmd = data[:1]
        self.length = data[1:5]
        self.password = data[5:len(data)]

class postgres(TcpHandler):
    NAME = "Postgres"
    DESCRIPTION = '''Postgres databases server. Records username, databasename and password to secrets.'''
    POSTGRES_VERSION = 1

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.ssl = True
        self.username = ''
        self.password = ''
        self.database = ''
        TcpHandler.__init__(self, *args)
        
    def _print_creds(self):
        if self.username != '':
            print("#" * 25)
            print("USERNAME: %s" % self.username)
            print("PASSWORD: %s" % self.password)
            print("DATABASE: %s" % self.database)
            print("#" * 25)
        
    def base_handle(self):
        data = self.handle_one_request()
        init = PostgresInitMessage(data)
        if init.ssl_enabled():
            #Check if request for SSL and settings say we support SSL
            print("Postgres: starting SSL connection")
            self.request.send('S')
            
            self.request = ssl.wrap_socket(self.request, keyfile=os.path.join(self.server.config.certkey), certfile=os.path.join(self.server.config.cert), server_side=True)
            startup = PostgresStartup(self.handle_one_request())
            self.username = startup.datapairs['user']
            self.database = startup.datapairs['database']
            print(self.username)
            
            #Enter a session to start reading incoming data packets
            auth = AuthenticationRequest(AUTH_REQ_PASSWORD)
            self.request.send(auth.packet)
            data = self.handle_one_request()
            authresp = AuthenticationResponse(data)
            self.password = authresp.password
        else:
            self.request.send(b'N')
            
        self._print_creds()
        return
            
   
               
        
        