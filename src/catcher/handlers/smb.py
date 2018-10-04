'''
Created on 15 Sep 2017

@author: gavin
'''
import logging
import re
import binascii

from random import randrange

from .basehandler import TcpHandler
from catcher.libs.responder.src.packets import *

logger = logging.getLogger(__name__)

def to_string(b):
    s = ""
    for i in list(b):
        s = s + '{:02x}'.format(i)
    return s
    
####################################################

class smb(TcpHandler):
    NAME = "SMB"
    DESCRIPTION = '''Responder handler. Records username and password to secrets. Code based on https://github.com/lgandx/Responder-Windows. Thanks to Laurent Gaffie!'''
    SETTINGS = {
            "challenge": "0B16212C37424D58"
        }
    
    def __init__(self, *args):
        '''
        Constructor
        https://docs.microsoft.com/en-us/windows/desktop/fileio/microsoft-smb-protocol-packet-exchange-scenario
        '''
        self.session = True
        self.challenge = bytes.fromhex(self.challenge)
        TcpHandler.__init__(self, *args)
        
        
    ##### Extract from Responder/servers/SMB.py ########
    #Function used to know which dialect number to return for NT LM 0.12
    def Parse_Nego_Dialect(self, data):
        Dialect = tuple([e.replace(b'\x00', b'') for e in data[40:].split(b'\x02')[:10]])
        for i in range(0, 16):
            if Dialect[i] == b'NT LM 0.12':
                return bytes([i]) + b'\x00'
    
    def midcalc(self, data):  #Set MID SMB Header field.
        return data[34:36]
    
    def uidcalc(self, data):  #Set UID SMB Header field.
        return data[32:34]
    
    def pidcalc(self, data):  #Set PID SMB Header field.
        return data[30:32]
    
    def tidcalc(self, data):  #Set TID SMB Header field.
        return data[28:30]
    
    def IsNT4ClearTxt(self, data, client):
        HeadLen = 36
    
        if data[14:16] == b"\x03\x80":
            SmbData = data[HeadLen+14:]
            WordCount = data[HeadLen]
            ChainedCmdOffset = data[HeadLen+1]
    
            if ChainedCmdOffset == b"\x75":
                PassLen = struct.unpack('<H',data[HeadLen+15:HeadLen+17])[0]
    
                if PassLen > 2:
                    Password = data[HeadLen+30:HeadLen+30+PassLen].replace(b"\x00",b"")
                    User = ''.join(tuple(data[HeadLen+30+PassLen:].split(b'\x00\x00\x00'))[:1]).replace(b"\x00",b"")
                    self.add_secret("Clear Text Username", User)
                    self.add_secret("Clear Text Password", Password)   
                    #print("[SMB] Clear Text Credentials: %s:%s" % (User, Password))
                    #WriteData(settings.Config.SMBClearLog % client, User+":"+Password, User+":"+Password)
    
    def Is_Anonymous(self, data):  # Detect if SMB auth was Anonymous
        SecBlobLen = struct.unpack('<H',data[51:53])[0]
    
        if SecBlobLen < 260:
            LMhashLen = struct.unpack('<H',data[89:91])[0]
            return LMhashLen in [0, 1]
        elif SecBlobLen > 260:
            LMhashLen = struct.unpack('<H',data[93:95])[0]
            return LMhashLen in [0, 1]
        
    def ParseSMBHash(self, data,client):  #Parse SMB NTLMSSP v1/v2
        SSPIStart  = data.find(b'NTLMSSP')
        SSPIString = data[SSPIStart:]
        LMhashLen    = struct.unpack('<H',data[SSPIStart+14:SSPIStart+16])[0]
        LMhashOffset = struct.unpack('<H',data[SSPIStart+16:SSPIStart+18])[0]
        #LMHash       = SSPIString[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
        LMHash       = to_string(SSPIString[LMhashOffset:LMhashOffset+LMhashLen]).upper()
        NthashLen    = struct.unpack('<H',data[SSPIStart+20:SSPIStart+22])[0]
        NthashOffset = struct.unpack('<H',data[SSPIStart+24:SSPIStart+26])[0]
        
        self.add_secret("LM Hash", LMHash)
    
        if NthashLen == 24:
            #SMBHash      = SSPIString[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
            SMBHash      = to_string(SSPIString[NthashOffset:NthashOffset+NthashLen]).upper()
            DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
            DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
            Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
            UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
            UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
            Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
            WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, LMHash, SMBHash, to_string(self.challenge))
    
            self.add_secret("Username", Domain+'\\'+Username)           
            self.add_secret("Client", client)
            self.add_secret("Hash", SMBHash)
            self.add_secret("Challenge", to_string(self.challenge))
            self.add_secret("NTLMv1-SSP Hash", WriteHash)
            
            #SaveToDb({
            #    'module': 'SMB', 
            #    'type': 'NTLMv1-SSP', 
            #    'client': client, 
            #    'user': Domain+'\\'+Username, 
            #    'hash': SMBHash, 
            #    'fullhash': WriteHash,
            #})
    
        if NthashLen > 60:
            SMBHash      = to_string(SSPIString[NthashOffset:NthashOffset+NthashLen]).upper()
            DomainLen    = struct.unpack('<H',SSPIString[30:32])[0]
            DomainOffset = struct.unpack('<H',SSPIString[32:34])[0]
            Domain       = SSPIString[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
            UserLen      = struct.unpack('<H',SSPIString[38:40])[0]
            UserOffset   = struct.unpack('<H',SSPIString[40:42])[0]
            Username     = SSPIString[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
            WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, to_string(self.challenge), SMBHash[:32], SMBHash[32:])
            
            self.add_secret("Username", Domain+'\\'+Username)
            self.add_secret("Client", client)
            self.add_secret("Hash", SMBHash)
            self.add_secret("Challenge", to_string(self.challenge))
            self.add_secret("NTLMv2-SSP Hash", WriteHash)
    
            #SaveToDb({
            #    'module': 'SMB', 
            #    'type': 'NTLMv2-SSP', 
            #    'client': client, 
            #    'user': Domain+'\\'+Username, 
            #    'hash': SMBHash, 
            #    'fullhash': WriteHash,
            #})
        
    def ParseShare(self, data):
        packet = data[:]
        a = re.search(b'(\\x5c\\x00\\x5c.*.\\x00\\x00\\x00)', packet)
        if a:
            self.add_secret("Share", a.group(0).decode('UTF-16LE'))
            #print("[SMB] Requested Share     : %s" % a.group(0).decode('UTF-16LE'))
            
    def GrabMessageID(self, data):
        Messageid = data[28:36]
        return Messageid
    
    def GrabCreditCharged(self, data):
        CreditCharged = data[10:12]
        return CreditCharged
    
    def GrabCreditRequested(self, data):
        CreditsRequested = data[18:20]
        if CreditsRequested == b"\x00\x00":
            ditsRequested =  b"\x01\x00"
        else:
            ditsRequested = data[18:20]
        return CreditsRequested
    
    def GrabSessionID(self, data):
        SessionID = data[44:52]
        return SessionID
    
    def ParseSMB2NTLMv2Hash(self, data,client):  #Parse SMB NTLMv2
        SSPIStart = data[113:]
        data = data[113:]
        LMhashLen = struct.unpack('<H',data[12:14])[0]
        LMhashOffset = struct.unpack('<H',data[16:18])[0]
        #LMHash = SSPIStart[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()
        LMHash = to_string(SSPIStart[LMhashOffset:LMhashOffset+LMhashLen]).upper()
        NthashLen = struct.unpack('<H',data[22:24])[0]
        NthashOffset = struct.unpack('<H',data[24:26])[0]
        #SMBHash = SSPIStart[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()
        SMBHash = to_string(SSPIStart[NthashOffset:NthashOffset+NthashLen]).upper()
        DomainLen = struct.unpack('<H',data[30:32])[0]
        DomainOffset = struct.unpack('<H',data[32:34])[0]
        Domain = SSPIStart[DomainOffset:DomainOffset+DomainLen].decode('UTF-16LE')
        UserLen      = struct.unpack('<H',data[38:40])[0]
        UserOffset   = struct.unpack('<H',data[40:42])[0]
        Username     = SSPIStart[UserOffset:UserOffset+UserLen].decode('UTF-16LE')
        WriteHash    = '%s::%s:%s:%s:%s' % (Username, Domain, to_string(self.challenge), SMBHash[:32], SMBHash[32:])
        self.add_secret("Username", Domain+'\\'+Username)
        self.add_secret("Hash", SMBHash)
        self.add_secret("Client", client)
        self.add_secret("Challenge", to_string(self.challenge))
        self.add_secret("NTLMv2-SSP Hash", WriteHash)
        #SaveToDb({
        #            'module': 'SMBv2', 
        #    'type': 'NTLMv2-SSP', 
        #    'client': client, 
        #    'user': Domain+'\\'+Username, 
        #    'hash': SMBHash, 
        #    'fullhash': WriteHash,
        #         })
            
    #########################################################
        
    def build_packet(self, header, body):         
        Packet = bytes(header) + bytes(body)
        length = struct.pack(">i", len(Packet))
        Buffer = length + Packet
        return Buffer
        
    def base_handle(self):
        self.request.settimeout(5.0)
        data = self.handle_raw_request()
            
        if not data:
            return
        
        if data[0] == b"\x81":  #session request 139
            self.debug("Session request")
            Buffer = b"\x82\x00\x00\x00"
            try:
                self.send_response(Buffer)
                data = self.handle_raw_request()
            except:
                pass
        
        while self.session is True:
            ############################## SMBv2 ##############################
            ##Negotiate proto answer SMBv2.         
            if data[8:10] == b"\x72\x00" and re.search(b"SMB 2.\?\?\?", data):
                self.set_fingerprint("smb")
                self.debug("SMBv2: Negotiate proto answer SMBv2.")
                head = SMB2Header(CreditCharge=b"\x00\x00",Credits=b"\x01\x00")
                t = SMB2NegoAns()
                t.calculate()
                packet = self.build_packet(head, t)
                self.send_response(packet)
                data = self.handle_raw_request()
                
            ## Session Setup 1 answer SMBv2.
            if data[16:18] == b"\x00\x00" and data[4:5] == b"\xfe":
                self.debug("SMBv2: Session Setup 1 answer SMBv2.")
                head = SMB2Header(MessageId=self.GrabMessageID(data), PID=b"\xff\xfe\x00\x00", CreditCharge=self.GrabCreditCharged(data), Credits=self.GrabCreditRequested(data))
                t = SMB2NegoAns(Dialect=b"\x10\x02")
                t.calculate()
                packet = self.build_packet(head, t)
                self.send_response(packet)
                data = self.handle_raw_request()
                
            ## Session Setup 2 answer SMBv2.
            if data[16:18] == b"\x01\x00" and data[4:5] == b"\xfe":
                self.debug("SMBv2: Session Setup 2 answer SMBv2.")
                head = SMB2Header(Cmd=b"\x01\x00", MessageId=self.GrabMessageID(data), PID=b"\xff\xfe\x00\x00", CreditCharge=self.GrabCreditCharged(data), Credits=self.GrabCreditRequested(data), SessionID=self.GrabSessionID(data),NTStatus=b"\x16\x00\x00\xc0")
                t = SMB2Session1Data(NTLMSSPNtServerChallenge=self.challenge)
                t.calculate()
                packet = self.build_packet(head, t)
                self.send_response(packet)
                data = self.handle_raw_request()
                
            ## Session Setup 3 answer SMBv2.
            if data[16:18] == b"\x01\x00" and self.GrabMessageID(data)[0:1] == b"\x02" and data[4:5] == b"\xfe":
                self.debug("SMBv2: Session Setup 3 answer SMBv2.")
                self.ParseSMB2NTLMv2Hash(data, self.client_address[0])
                head = SMB2Header(Cmd=b"\x01\x00", MessageId=self.GrabMessageID(data), PID=b"\xff\xfe\x00\x00", CreditCharge=self.GrabCreditCharged(data), Credits=self.GrabCreditRequested(data), NTStatus=b"\x22\x00\x00\xc0", SessionID=self.GrabSessionID(data))
                t = SMB2Session2Data()
                packet = self.build_packet(head, t)
                self.send_response(packet)
                data = self.handle_raw_request()
            
            ############################## SMBv1 ##############################
            ##Negotiate proto answer.
            if data[8:10] == b"\x72\x00" and data[4:5] == b"\xff" and re.search(b"SMB 2.\?\?\?", data) == None:
                self.set_fingerprint("smb")
                self.debug("SMBv1: Negotiate Protocol")
                Header = SMBHeader(cmd=b"\x72",flag1=b"\x88", flag2=b"\x01\xc8", pid=self.pidcalc(data), mid=self.midcalc(data))
                Body = SMBNegoKerbAns(Dialect=self.Parse_Nego_Dialect(data))
                Body.calculate()
                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()
                
            if data[8:10] == b"\x73\x00" and data[4:5] == b"\xff":  # Session Setup AndX Request smbv1
                self.debug("SMBv1: Session Setup AndX")
                self.IsNT4ClearTxt(data, self.client_address[0])
                
                # STATUS_MORE_PROCESSING_REQUIRED
                Header = SMBHeader(cmd=b"\x73",flag1=b"\x88", flag2=b"\x01\xc8", errorcode=b"\x16\x00\x00\xc0", uid=bytes([randrange(256)])+bytes([randrange(256)]),pid=self.pidcalc(data),tid=b"\x00\x00",mid=self.midcalc(data))
                #if settings.Config.CaptureMultipleCredentials and self.ntry == 0:
                #    Body = SMBSession1Data(NTLMSSPNtServerChallenge=settings.Config.Challenge, NTLMSSPNTLMChallengeAVPairsUnicodeStr="NOMATCH")
                #else:
                Body = SMBSession1Data(NTLMSSPNtServerChallenge=self.challenge)
                Body.calculate()
                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()
                
            if data[8:10] == b"\x73\x00" and data[4:5] == b"\xff":  # STATUS_SUCCESS
                self.debug("SMBv1: STATUS_SUCCESS")
                if self.Is_Anonymous(data):
                    self.debug("SMBv1: Annonymous")
                    Header = SMBHeader(cmd=b"\x73",flag1=b"\x98", flag2=b"\x01\xc8",errorcode=b"\x72\x00\x00\xc0",pid=self.pidcalc(data),tid=b"\x00\x00",uid=self.uidcalc(data),mid=self.midcalc(data))###should always send errorcode="\x72\x00\x00\xc0" account disabled for anonymous logins.
                    Body = SMBSessEmpty()
                    packet = self.build_packet(Header, Body)
                    self.send_response(packet)
                else:
                    # Parse NTLMSSP_AUTH packet
                    self.debug("SMBv1: NTLMSSP_AUTH")
                    self.ParseSMBHash(data,self.client_address[0])

                    # Send STATUS_SUCCESS
                    Header = SMBHeader(cmd=b"\x73",flag1=b"\x98", flag2=b"\x01\xc8", errorcode=b"\x00\x00\x00\x00",pid=self.pidcalc(data),tid=self.tidcalc(data),uid=self.uidcalc(data),mid=self.midcalc(data))
                    Body = SMBSession2Accept()
                    Body.calculate()

                    packet = self.build_packet(Header, Body)
                    self.send_response(packet)
                    data = self.handle_raw_request()
                    
            if data[8:10] == b"\x75\x00" and data[4:5] == b"\xff":  # Tree Connect AndX Request
                self.debug("SMBv1: Tree Connect AndX Request")
                self.ParseShare(data)
                Header = SMBHeader(cmd=b"\x75",flag1=b"\x88", flag2=b"\x01\xc8", errorcode=b"\x00\x00\x00\x00", pid=self.pidcalc(data), tid=bytes([randrange(256)])+bytes([randrange(256)]), uid=self.uidcalc(data), mid=self.midcalc(data))
                Body = SMBTreeData()
                Body.calculate()

                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()
                
                #Check for Trans2 request
                
            if data[8:10] == b"\x71\x00" and data[4:5] == b"\xff":  #Tree Disconnect
                self.debug("SMBv1: Tree Disconnect")
                Header = SMBHeader(cmd=b"\x71",flag1=b"\x98", flag2=b"\x07\xc8", errorcodeb="\x00\x00\x00\x00",pid=self.pidcalc(data),tid=self.tidcalc(data),uid=self.uidcalc(data),mid=self.midcalc(data))
                Body = "\x00\x00\x00"

                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()

            if data[8:10] == b"\xa2\x00" and data[4:5] == b"\xff":  #NT_CREATE Access Denied.
                self.debug("SMBv1: NT_CREATE Access Denied")
                Header = SMBHeader(cmd=b"\xa2",flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x22\x00\x00\xc0",pid=self.pidcalc(data),tid=self.tidcalc(data),uid=self.uidcalc(data),mid=self.midcalc(data))
                Body = b"\x00\x00\x00"

                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()

            if data[8:10] == b"\x25\x00" and data[4:5] == b"\xff":  # Trans2 Access Denied.
                self.debug("SMBv1: Trans2 Access Denied")
                Header = SMBHeader(cmd=b"\x25",flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x22\x00\x00\xc0",pid=self.pidcalc(data),tid=self.tidcalc(data),uid=self.uidcalc(data),mid=self.midcalc(data))
                Body = b"\x00\x00\x00"

                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()
            
            if data[8:10] == b"\x74\x00" and data[4:5] == b"\xff":  # LogOff
                self.debug("SMBv1: Logoff")
                Header = SMBHeader(cmd=b"\x74",flag1=b"\x98", flag2=b"\x07\xc8", errorcode=b"\x22\x00\x00\xc0",pid=self.pidcalc(data),tid=self.tidcalc(data),uid=self.uidcalc(data),mid=self.midcalc(data))
                Body = b"\x02\xff\x00\x27\x00\x00\x00"

                packet = self.build_packet(Header, Body)
                self.send_response(packet)
                data = self.handle_raw_request()
            ###################################################################
            
            self.session = False
            
            
            

