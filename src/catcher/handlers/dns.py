'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import UdpHandler
from dnslib import DNSRecord, DNSRecord, DNSHeader, DNSQuestion, RR, A
from catcher.settings import LISTEN_IP

import binascii
import logging
import re

logger = logging.getLogger(__name__)

class dns(UdpHandler):
    '''
    Handles incoming connections and keeps it open
    '''
    RESOLVED_IP = LISTEN_IP

    def __init__(self, *args):
        '''
        Constructor
        '''
        UdpHandler.__init__(self, *args)
        
    def base_handle(self):
        data = self.handle_raw_request()
        if len(data) > 0:
            try:
                dnsrequest = DNSRecord.parse(data)
                header = dnsrequest.header
                question = dnsrequest.get_q()
                questionname = question.get_qname()
                resolvedip = self.get_resolved_ip(str(questionname))

                resp = DNSRecord(
                        DNSHeader(qr=1,aa=1,ra=1,id=header.id),
                        q=question,
                        a=RR(questionname,rdata=A(resolvedip))
                    )
                self.send_response(resp.pack())
            except Exception as e:
                logger.error(e)

    def get_resolved_ip(self, qname=None):
        if qname is not None:
            self.add_secret("Domain lookup", qname)
            if "local" in qname:
                logger.info("Static resolving {} to 127.0.0.1".format(qname))
                return "127.0.0.1"
            if "dynamic" in qname:
                try:
                    hexdata = qname.split('.')[1]
                    resolve = binascii.a2b_hex(hexdata).decode("utf-8")
                    logger.info("Dynamic resolving {} to {}".format(qname, resolve))
                    return resolve
                except:
                    logger.info("Dynamic resolving {} - FAILED".format(qname))
                    return "127.0.0.1"
            if "exfil" in qname:
                try:
                    hexdata = qname.split('.')[1]
                    if re.match('[0-9a-fA-F]{2}', hexdata):   
                        logger.info("Extracting data from DNS entry")
                        raw = binascii.a2b_hex(hexdata)
                        self.add_secret("DNS Data Exfiltration", raw.decode("utf-8"))
                except:
                    logger.info("Extracting data from {} - FAILED".format(qname))
                return "127.0.0.1"
        elif self.RESOLVED_IP:
            return self.RESOLVED_IP
        return self.server.socket.getsockname()[0]

