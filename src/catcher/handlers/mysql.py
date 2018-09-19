'''
Created on 15 Sep 2017

@author: gavin

https://www.safaribooksonline.com/library/view/understanding-mysql-internals/0596009577/ch04s04.html
http://m.blog.csdn.net/u011130746/article/details/66970086
https://dev.mysql.com/doc/internals/en/secure-password-authentication.html
https://dev.mysql.com/doc/internals/en/old-password-authentication.html#packet-Authentication::Old
'''
import struct
import binascii

from .basehandler import TcpHandler

class mysql(TcpHandler):
    NAME = "MySQL"
    DESCRIPTION = '''Handles incoming MySQL connections. Records username and password to secrets.'''
    SETTINGS = {
        'version': '5.1.66', 
        'salt': '\x41\x41\x41\x41\x41\x41\x41\x41\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42'
    }

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_greeting_packet()
         
        while self.session is True:
            data = self.handle_raw_request()
            self.read_auth_packet(data)
            break
            
    def send_greeting_packet(self):
        '''
        Send the typical mysql greetings packets
        '''
        protocol = '\x0a'
        version = '\x35\x2e\x30\x2e\x35\x34\x00' #'5.1.66'
        if self.version:
            version = self.version + '\x00' #'5.1.66'
        threadid = '\x5e\x00\x00\x00'
        salt = self.salt[:8] + '\x00'
        capabilities = '\x2c\xa2'
        lang = '\x21'
        status = '\x02\x00'
        ex_capabilities = '\x00\x00'
        auth_plugin_len = '\x00'
        unused = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        ex_salt = self.salt[-12:] + '\x00'
        
        body = protocol + version + threadid + salt + capabilities + lang + status + ex_capabilities + auth_plugin_len + unused + ex_salt
        print(repr(body))
        header = self.mysql_header(body)
        packet = header + body.encode()
        self.send_response(packet)
        
    def mysql_header(self, body, seq=None):
        if not seq:
            seq = 0
        header = bytearray(3)
        struct.pack_into('<h', header, 0, len(body))
        header.append(seq)
        return header
    
    def read_auth_packet(self, data):
        '''
        Extracts the username and password
        password = 'password'
        SHA1( password ) XOR SHA1( "AAAAAAAABBBBBBBBBBBB" <concat> SHA1( SHA1( password ) ) )
        
        '''
        try:
            creds = data[36:]
            username = ''
            hash = ''
            database = ''
    
            username, passndb = creds.split(b'\x00', 1)
            hash = binascii.hexlify(passndb[:21])
            database = passndb[21:].strip(b'\x00')
    
            self.add_secret("MySQL Username", username)
            self.add_secret("MySQL Password Hash", hash)
            self.add_secret("MySQL Database", database)
        except:
            #probably a bad packet, end session
            self.session = False
               
        
        