'''
Created on 15 Sep 2017

@author: gavin
'''
import binascii
from basehandler import UdpHandler
from dnslib import DNSRecord, DNSRecord, DNSHeader, DNSQuestion, RR, A

class dns(UdpHandler):
    '''
    Handles incoming connections and keeps it open
    '''
    RESOLVED_IP = None

    def __init__(self, *args):
        '''
        Constructor
        '''
        UdpHandler.__init__(self, *args)
        
    def base_handle(self):
        data = self.handle_one_request()
        if len(data) > 0:
            try:
                print "Got DNS request"
                dnsrequest = DNSRecord.parse(data)
                header = dnsrequest.header
                question = dnsrequest.get_q()
                questionname = question.get_qname()
                resolvedip = self.get_resolved_ip()
                
                resp = DNSRecord(
                        DNSHeader(qr=1,aa=1,ra=1,id=header.id),
                        q=question,
                        a=RR(questionname,rdata=A(self.get_resolved_ip()))
                    )
                #socket.sendto(resp.pack(), self.client_address)
                self.send_response(resp.pack())
            except Exception, e:
                raise
                
    def get_resolved_ip(self):
        if self.RESOLVED_IP:
            return self.RESOLVED_IP   
        return self.server.socket.getsockname()[0]
