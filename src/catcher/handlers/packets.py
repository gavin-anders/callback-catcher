import struct
import collections
from collections import OrderedDict
import binascii

############# CONST ################
# SMB Commands
SMB_COM_TREE_CONNECT        = b'\x70'
SMB_COM_TREE_DISCONNECT     = b'\x71'
SMB_COM_NEGOTIATE           = b'\x72'
SMB_COM_SESSION_SETUP_ANDX  = b'\x73'
SMB_COM_LOGOFF_ANDX         = b'\x74'
SMB_COM_TREE_CONNECT_ANDX   = b'\x75'
# SMB Flags
SMB_FLAGS_REPLY             = b'\x80'

#####################################

class Packet(object):
    def __init__(self):
        self.packet = None
        
    def get_bytes(self):
        return bytearray(self.packet)
    
class MySql(Packet):
    def __init__(self):
        self.seq = 0
        self.header = bytearray(3)

    def set_header(self, body, seq=None):
        if seq:
            self.seq = self.seq + 1
        struct.pack_into('<h', self.header, 0, len(body))
        self.header.append(self.seq)
        print(type(self.header))
        
    def set_body(self, data):
        self.set_header(data)
        print(type(data))
        self.packet = self.header + bytes(data)

class MySqlGeetingPacket(MySql):
    def __init__(self, version, salt):
        MySql.__init__(self)
        s = bytearray(salt, 'utf8')
        self.protocol =        b'\x0a'
        self.version =         bytearray(version, 'utf8') + b'\x00' #version string followed by null byte
        self.threadid =        b'\x5e\x00\x00\x00'
        self.salt = s[:8] +    b'\x00'    #split and take first 8 bytes
        self.capabilities =    b'\x2c\xa2'
        self.lang =            b'\x21'
        self.status =          b'\x02\x00'
        self.ex_capabilities = b'\x00\x00'
        self.auth_plugin_len = b'\x00'
        self.unused =          b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.ex_salt =         s[-12:] + b'\x00'   #remainder of the split sal
        self.set_body(self.protocol + self.version + self.threadid + self.salt + self.capabilities + self.lang + self.status + self.ex_capabilities + self.auth_plugin_len + self.unused + self.ex_salt)
    
############################################################
"""class OrderedPacket(object):
    def __new__(cls, *args, **kwargs):
        instance = object.__new__(cls)
        instance.__packet__ = OrderedDict()
        return instance

    def __setattr__(self, key, value):
        if key != '__packet__':
            self.__packet__[key] = value
        object.__setattr__(self, key, value)
        
    def __dict__(self):
        return self.__packet__

    def keys(self):
        return self.__packet__.keys()

    def iteritems(self):
        return self.__packet__.items()
    
    def get_bytes(self):
        p = b''
        for k,v in self.__packet__.items():
            p = p + v
        return p
        
    def read_bytes(self, data, offset=0):
        '''
        Maps raw bytes to already defined subclass variables
        '''
        for k, v in self.__packet__.items():
            setattr(self, k, data[offset:offset+len(v)])
            offset = offset + len(v)

class SMBHeader(OrderedPacket):
    '''
    #Represents the 32-bytes SMB Header
    #https://msdn.microsoft.com/en-us/library/ee441774.aspx
    '''
    def __init__(self):
        self.protocolid       = bytearray(4) 
        self.command          = bytearray(1)
        self.status           = bytearray(4)
        self.flags            = bytearray(1)
        self.flags2           = bytearray(2)
        self.pidhigh          = bytearray(2)
        self.secruityfeatures = bytearray(8)
        self.reserved         = bytearray(2)
        self.tid              = bytearray(2)
        self.pidlow           = bytearray(2)
        self.uid              = bytearray(2)"""