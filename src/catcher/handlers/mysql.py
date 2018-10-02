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
from .packets import MySqlGeetingPacket

class mysql(TcpHandler):
    NAME = "MySQL"
    DESCRIPTION = '''Handles incoming MySQL connections. Records username and password to secrets.'''
    SETTINGS = {
        'version': '5.1.66', 
        'salt': 'AAAAAAAABBBBBBBBBBBB'
    }

    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        authpacket = MySqlGeetingPacket(version=self.version, salt=self.salt)
        self.send_response(authpacket.get_bytes())
        self.set_fingerprint()
         
        while self.session is True:
            data = self.handle_raw_request()
            self.read_auth_packet(data)
            break
    
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
               
        
        