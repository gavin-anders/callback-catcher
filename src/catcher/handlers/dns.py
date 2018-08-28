'''
Created on 15 Sep 2017

@author: gavin
'''
from .basehandler import UdpHandler
from dnslib import DNSRecord, DNSRecord, DNSHeader, DNSQuestion, RR, A
from catcher.settings import LISTEN_IP

import binascii

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
        data = self.handle_one_request()
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
                raise

    def get_resolved_ip(self, qname=None):
        if qname is not None:
            if "local" in qname:
                print("Static resolving %s to 127.0.0.1:22" % qname)
                return "127.0.0.1"
            if "dynamic" in qname:
                try:
                    hexdata = domain.split('.')[1]
                    resolve = str(binascii.a2b_hex(hexdata)).strip()
                    print("Dynamic resolving %s to %s" % (qname, resolve))
                    return resolve
                except:
                    return "127.0.0.1"
        elif self.RESOLVED_IP:
            return self.RESOLVED_IP
        return self.server.socket.getsockname()[0]

