'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import TcpHandler

import binascii

logger = logging.getLogger(__name__)

class rawresponse(TcpHandler):
    NAME = "Raw Response"
    DESCRIPTION = '''Responds with the hex contents of what was provided in the settings. Format should be 4141'''
    SETTINGS = {
        'banner': None,
        'data': None,
    }
    def __init__(self, *args):
        self.session = True
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        self.send_response(self.banner)
        
        while self.session is True:
            req = self.handle_request()
            if req:
                try:
                    data = binascii.unhexlify(self.data)
                    self.send_response(data)
                except binascii.Error:
                    logger.error("Binascii error decoding data settings as hex")
                except Exception as e:
                    logger.error(str(e))