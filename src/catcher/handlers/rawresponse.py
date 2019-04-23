'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import TcpHandler

import binascii
import logging

logger = logging.getLogger(__name__)

class rawresponse(TcpHandler):
    NAME = "Raw Response"
    DESCRIPTION = '''Responds with the hex contents of what was provided in the settings. Format should be 4141'''
    CONFIG = {
        'banner': None,
        'data': None,
    }
    def __init__(self, *args):
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        try:
            if self.banner is not None:
                banner = binascii.unhexlify(self.banner)
                self.send_response(banner)
            
            req = self.handle_request()
            if req:
                self.send_response(binascii.unhexlify(self.data))
        except binascii.Error:
            logger.error("Binascii error decoding value as hex")
        except Exception as e:
            logger.error(str(e))
                