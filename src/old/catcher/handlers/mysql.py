'''
Created on 15 Sep 2017

@author: gavin

https://www.safaribooksonline.com/library/view/understanding-mysql-internals/0596009577/ch04s04.html
http://m.blog.csdn.net/u011130746/article/details/66970086
'''
import struct
import binascii

from basehandler import TcpHandler

class mysql(TcpHandler):
    '''
    Handles incoming connections and keeps it open
    '''
    MYSQL_VERSION = '5.1.66'
    SALT = '\x41\x41\x41\x41\x41\x41\x41\x41\x00'
    SALT_EX = '\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x42\x00'

    def __init__(self, *args):
        '''
        Constructor
        '''
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_greeting_packet()
         
        while True:
            data = self.handle_one_request()
            self.read_auth_packet(data)
            break
            
    def send_greeting_packet(self):
        '''
        Send the typical mysql greetings packets
        '''
        protocol = '\x0a'
        version = '\x35\x2e\x30\x2e\x35\x34\x00' #'5.1.66'
        threadid = '\x5e\x00\x00\x00'
        salt = self.SALT
        capabilities = '\x2c\xa2'
        lang = '\x21'
        status = '\x02\x00'
        ex_capabilities = '\x00\x00'
        auth_plugin_len = '\x00'
        unused = '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        ex_salt = self.SALT_EX
        
        body = protocol + version + threadid + salt + capabilities + lang + status + ex_capabilities + auth_plugin_len + unused + ex_salt
        header = self.mysql_header(body)
        packet = header + body
        self.request.send(packet)
        
    def mysql_header(self, body, seq=None):
        if not seq:
            seq = 0
        header = bytearray(3)
        struct.pack_into('<h', header, 0, len(body))
        header.append(seq)
        print binascii.hexlify(header)
        return header
    
    def read_auth_packet(self, data):
        '''
        Extracts the username and password
        '''
        creds = data[36:]   #this isnt correct according to the docs, but all tests indicate offset 36
        username = ''
        hash = ''
        database = ''
        #Get username
        for k, b in enumerate(list(creds)):
            
            if b.encode('hex') == '00':
                hash = creds[k:]
                break
            else:
                username = username + b
                
        #get password
        hash = binascii.hexlify(creds[k+1:k+21])
        database = creds[k+22:]
                
        print "#####################################"
        print 'USERNAME:\t%s' % username
        print 'PASS HASH:\t%s' % hash
        print 'PASS SALT:\t%s' % self.SALT[:-1] + self.SALT_EX[:-1]
        print 'DATABASE:\t%s' % database
        print "#####################################"
               
        
        