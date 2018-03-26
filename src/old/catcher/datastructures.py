'''
Created on 14 Dec 2017

@author: gavin
'''
import base64
import datetime

class Callback(object):
    '''
    Represents a single callback
    Use __dict__ to get the dictionary
    '''

    def __init__(self, clientaddress, serveraddress, protocol, data, listenerid):
        self.sourceip     = clientaddress[0]
        self.sourceport   = clientaddress[1]
        self.serverip     = serveraddress[0]
        self.serverport   = serveraddress[1]
        self.timestamp    = str(datetime.datetime.now())
        self.protocol     = protocol
        self.data         = data
        self.datasize     = len(data)
        self.client       = listenerid
        self.secrets      = []
        
    def append_packet(self, packet):
        d = base64.b64decode(self.data) + packet
        self.data = base64.b64encode(d)
        
    def append_secret(self, item):
        self.secrets.append(item)
        
        
class Settings(object):
    '''
    Represents a dict of settings
    '''

    def __init__(self, **kwargs):
        self.values = kwargs
        
        
class Secret(object):
    '''
    Represents a single secret item
    Use __dict__ to get the dictionary
    '''

    def __init__(self, name, value):
        self.name   = name
        self.value  = value
        
        
class Log(object):
    '''
    Represents a single log item
    Use __dict__ to get the dictionary
    '''

    def __init__(self, record, identifier):
        self.client       = identifier
        self.threadname   = record.__dict__['threadName']
        self.processname  = record.__dict__['processName']
        self.name         = record.__dict__['name']
        self.created_time = str(datetime.datetime.now())
        self.level        = record.__dict__['levelname']
        self.message      = record.__dict__['msg']
        self.line         = record.__dict__['lineno']
        self.file         = record.__dict__['filename']
    
        
if __name__ == "__main__":
    cb = Callback(
        ('127.0.0.1', 1234),
        ('1.1.1.1', 1234),
        'tcp',
        'AAAAAAAAAAAAAAAAAAAAAAAAAAAAA'
        )
    print cb.__dict__