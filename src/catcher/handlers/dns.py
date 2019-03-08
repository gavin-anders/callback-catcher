'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import UdpHandler
from dnslib import DNSRecord, DNSRecord, DNSHeader, DNSQuestion, RR, A

import binascii
import logging
import re

logger = logging.getLogger(__name__)

class dns(UdpHandler):
    NAME = "DNS Server"
    DESCRIPTION = "Basic UDP domain server. Responds to A records, supports data DNS exfil and dynamic resolving via hex encoded subdomain values (max length 53 chars)."
    SETTINGS = {
        "resolveip": "13.59.5.95",
        "exclude": ["ns1.pentestlabs.uk.", "pentestlabs.uk.", "www.pentestlabs.uk."]
    }

    def __init__(self, *args):
        '''
        Constructor
        '''
        UdpHandler.__init__(self, *args)
        
    def base_handle(self):
        data = self.handle_request()
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
                self.set_fingerprint()
                self.send_response(resp.pack())
            except Exception as e:
                logger.error(e)

    def get_resolved_ip(self, qname=None):
        if qname is not None:
            if qname in self.exclude: #dont log
                return self.resolveip
                
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
                        self.add_secret("Data Exfiltration", raw.decode("utf-8"))
                except:
                    logger.info("Extracting data from {} - FAILED".format(qname))
                return "127.0.0.1"
        return self.resolveip

