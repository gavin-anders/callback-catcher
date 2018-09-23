import struct

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
        self.protocol = b'\x0a'
        self.version = bytearray(version, 'utf8') + b'\x00' #version string followed by null byte
        self.threadid = b'\x5e\x00\x00\x00'
        self.salt = s[:8] + b'\x00'    #split and take first 8 bytes
        self.capabilities = b'\x2c\xa2'
        self.lang = b'\x21'
        self.status = b'\x02\x00'
        self.ex_capabilities = b'\x00\x00'
        self.auth_plugin_len = b'\x00'
        self.unused = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
        self.ex_salt = s[-12:] + b'\x00'   #remainder of the split sal
        self.set_body(self.protocol + self.version + self.threadid + self.salt + self.capabilities + self.lang + self.status + self.ex_capabilities + self.auth_plugin_len + self.unused + self.ex_salt)
