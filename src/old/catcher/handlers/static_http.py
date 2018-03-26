'''
Created on 15 Sep 2017

@author: gavin
'''

from basehandler import TcpHandler

class static_http(TcpHandler):
    '''
    Handles incoming connections as a session and echo incoming data
    '''
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.session = True
        self.headers = [
                    ('Server', 'CallBackCatcher'),
                    ('Test', 'AAAAAAAAAAAAAAAAA')
                ]
        self.resp = "HTTP/1.1 200 OK"
        self.content = """<html><body>This is a page</body></html>"""
        TcpHandler.__init__(self, *args)
        
    def base_handle(self):
        data = self.handle_one_request()
        self.request.send(self._build_response(self.resp, self.headers, self.content))
        
    def _build_response(self, resp, headers, content):
        '''
        Returns response for status 200
        '''
        response = self.resp + "\r\n"
        for item in headers:
            header = "%s: %s\r\n" % item
            response = response + header
        response = response + "Connection: Close\r\n"
        response = response + "\r\n"
        response = response + content 
        response = response + "\r\n"
        return response
        