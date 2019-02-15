'''
Created on 15 Sep 2017

@author: gavin
'''

from .basehandler import TcpHandler

class basehttp(TcpHandler):
    NAME = "Base HTTP"
    DESCRIPTION = '''A basic HTTP handler and server based on python's BaseHTTPServer.py. Doesnt do anything other that return 400 responses. A base class that should be inherited.'''
    SETTINGS = {
        'default_content_type': 'text/html',
        'detect_content_type': True,
        'force_keep_alive': False,
        'default_code': 400
    }
    
    response_codes = {
        100: ('Continue', 'Request received, please continue'),
        101: ('Switching Protocols', 'Switching to new protocol; obey Upgrade header'),
        200: ('OK', 'Request fulfilled, document follows'),
        201: ('Created', 'Document created, URL follows'),
        202: ('Accepted', 'Request accepted, processing continues off-line'),
        203: ('Non-Authoritative Information', 'Request fulfilled from cache'),
        204: ('No Content', 'Request fulfilled, nothing follows'),
        205: ('Reset Content', 'Clear input form for further input.'),
        206: ('Partial Content', 'Partial content follows.'),
        300: ('Multiple Choices', 'Object has several resources -- see URI list'),
        301: ('Moved Permanently', 'Object moved permanently -- see URI list'),
        302: ('Found', 'Object moved temporarily -- see URI list'),
        303: ('See Other', 'Object moved -- see Method and URL list'),
        304: ('Not Modified', 'Document has not changed since given time'),
        305: ('Use Proxy', 'You must use proxy specified in Location to access this resource.'),
        307: ('Temporary Redirect', 'Object moved temporarily -- see URI list'),
        400: ('Bad Request','Bad request syntax or unsupported method'),
        401: ('Unauthorized', 'No permission -- see authorization schemes'),
        402: ('Payment Required', 'No payment -- see charging schemes'),
        403: ('Forbidden',  'Request forbidden -- authorization will not help'),
        404: ('Not Found', 'Nothing matches the given URI'),
        405: ('Method Not Allowed', 'Specified method is invalid for this resource.'),
        406: ('Not Acceptable', 'URI not available in preferred format.'),
        407: ('Proxy Authentication Required', 'You must authenticate with ' 'this proxy before proceeding.'),
        408: ('Request Timeout', 'Request timed out; try again later.'),
        409: ('Conflict', 'Request conflict.'),
        410: ('Gone', 'URI no longer exists and has been permanently removed.'),
        411: ('Length Required', 'Client must specify Content-Length.'),
        412: ('Precondition Failed', 'Precondition in headers is false.'),
        413: ('Request Entity Too Large', 'Entity is too large.'),
        414: ('Request-URI Too Long', 'URI is too long.'),
        415: ('Unsupported Media Type', 'Entity body in unsupported format.'),
        416: ('Requested Range Not Satisfiable',  'Cannot satisfy request range.'),
        417: ('Expectation Failed', 'Expect condition could not be satisfied.'),
        500: ('Internal Server Error', 'Server got itself in trouble'),
        501: ('Not Implemented',  'Server does not support this operation'),
        502: ('Bad Gateway', 'Invalid responses from another server/proxy.'),
        503: ('Service Unavailable', 'The server cannot process the request due to a high load'),
        504: ('Gateway Timeout', 'The gateway server did not receive a timely response'),
        505: ('HTTP Version Not Supported', 'Cannot fulfill request.'),
    }
    
    DEFAULT_ERROR_MESSAGE = ("<html><head><title>Error response</title>"
    "</head><body><h1>Error response</h1><p>Error code {code}."
    "<p>Message: {message}."
    "<p>Error code explanation: {code} = {explain}.</body></html>")
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.req_raw = None
        self.req_command = ""
        self.req_path = ""
        self.req_version = ""
        self.req_headers = []
        self.req_body = None
        
        self.resp_headers = []
        
        TcpHandler.__init__(self, *args)
        
    def parse_http_request(self, data=None):
        """
        parses the request and returns True False if its a good or bad request
        will return a 400 if its a bad request
        :return: True or False
        """
        if data is None:
            data = self.handle_request().decode('utf-8')    #get the next bit of data if the child class didnt both
            
        if not data:
            return
        
        self.req_raw = data
        
        try:
            # parse request line
            raw = data.splitlines()
            reqline = raw.pop(0).split(" ")
            if len(reqline) == 3: #probably a HTTP/1.x
                [command, path, version] = reqline
                if version[:5] != 'HTTP/':
                    self.send_error(400, "Bad request version {}".format(version))
                    return False
                
                try:
                    base_version_number = version.split('/', 1)[1]
                    version_number = base_version_number.split(".")
                    if len(version_number) != 2:
                        raise ValueError
                    version_number = int(version_number[0]), int(version_number[1])
                except (ValueError, IndexError):
                    self.send_error(400, "Bad request version ({})".format(version))
                    return False
                
                #if version_number >= (1, 1) and self.protocol_version >= "HTTP/1.1":
                #    self.close_connection = 0
                if version_number >= (2, 0):
                    self.send_error(505, "Invalid HTTP Version ({})".format(base_version_number))
                    return False
            elif len(reqline) == 2: # probably a HTTP/0.9
                self.set_fingerprint('HTTP/0.9')
                [command, path] = reqline
                if command != 'GET':
                    self.send_error(400, "Bad HTTP/0.9 request type ({})".format(command))
            elif not reqline:
                return False
            else:
                self.send_error(400, "Bad request syntax ({})".format(requestline))
                return False
            self.req_command, self.req_path, self.req_version = command, path, version
            
            #conntype = self.req_headers.get('Connection', "")
            #if conntype.lower() == 'close':
            #    self.close_connection = 1
            #elif (conntype.lower() == 'keep-alive' and self.protocol_version >= "HTTP/1.1"):
            #    self.close_connection = 0
            
            # parse headers
            for h in raw:
                if ":" in h:
                    x = h.split(":", 2)
                    self.add_resp_header(x[0], x[1].strip())       
                    
            # parse the body if there is one
            content_length = self.get_req_header("Content-length")
            if content_length is not None:
                header, body = data.split('\r\n', 1)
                self.req_body = body[:int(content_length)]
            
            method = getattr(self, "do_" + command.strip())
            method()
            
            return True
        except AttributeError:
            self.debug("You dont have code that can handle that verb. Try defining a do_{}() method".format(command))
            self.send_error(400)
        except:
            self.send_error(500)
        return False

    def add_resp_header(self, name, value):
        """
        Adds a header to the resp header list.
        Overwrites the header value if already exists
        Bug: doesnt maintain case values
        """
        for h in self.resp_headers:
            if h['header'].lower() == name.lower():
                self.debug("Replacing header value for: {}".format(name))
                h['value'] = value
                return
        self.resp_headers.append({'header': name, 'value': value})
        
    def get_req_header(self, name):
        """
        Gets the header value from the req_headers
        :return: header dictionary
        """
        for h in self.req_headers:
            if h['header'] == name.lower():
                return h
        return None
    
    def send_error(self, code, message=None, content=None):
        """
        Sends back a simple error page
        """
        try:
            short, long = self.response_codes[code]
        except KeyError:
            short, long = '???', '???'
            
        if message:
            message = short
            
        explain = long

        if not content:
            content = (self.DEFAULT_ERROR_MESSAGE.format(code=code, message=message, explain=explain))
            
        self.add_resp_header("Content-type", self.default_content_type)
        
        if self.req_command != 'HEAD' and code >= 200 and code not in (204, 304):
            self.send_http_response(code, content)
        else:
            self.send_http_response(code)
        
    def send_http_response(self, code=200, content=None):
        """
        Build response with headers and content detection
        """
        ###################################
        ### ADD CODE TO DETECT SUBCLASSES USING HEADERS
        ###################################
        
        response = str.encode('{} {}\r\n'.format(self.req_version, self.response_codes[code][0]))
        
        if content is not None:
            content_type = self.default_content_type
            if self.detect_content_type is True:
                try:
                    content_type = magic.from_buffer(content, mime=True)
                    logger.debug("Autodetect HTTP response content-type '{}'".format(content_type))
                except:
                    pass
            self.add_resp_header("Content-type", content_type)
               
        if self.force_keep_alive is True:
            self.add_resp_header("Connection", "Keep-alive")
        
        #build headers from list
        for h in self.resp_headers:
            header = "{}: {}\r\n".format(h['header'], h['value'])
            response = response + header.encode()
            
        response = response + b"\r\n"    
        
        #build body
        if content:
            response = response + content.encode()
            response = response + b"\r\n"
        self.send_response(response)
    
    def base_handle(self):
        """
        Dummy class to be overwritten
        """
        self.parse_http_request()
