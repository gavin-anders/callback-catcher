import os
import logging
import magic
import re
import base64
from .basehttphandler import basehttphandler
import catcher.settings as SETTINGS

logger = logging.getLogger(__name__)

class http(basehttphandler):
    NAME = "HTTP Basic"
    DESCRIPTION = '''A HTTP server that responds with files and content from a local directory.'''
    CONFIG = {
        'default_page': '<html><body>Catcher HTTP Handler</body></html>',
        'dir_browsing': True,
        'payloadfile': '/tmp/payloads.txt',
        'payloaddir': '/tmp/payloads/',
    }
    DIR_INDEX_PAGE = ('<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 3.2 Final//EN">'
        '<html>'
        '<head>'
        '<title>Index of $DIR$</title>'
        '</head>'
        '<body>'
        '<h1>Index of $DIR$</h1>'
        '<table>'
        '<tr><td><a href="$BASEDIR$"><b>Parent Directory</b></a></td></tr>'
        '$FILELIST$'
        '</table>'
        '</body>'
        '</html>')
    
    def __init__(self, *args):
        '''
        Constructor
        '''
        self.www_root = os.path.join(SETTINGS.HANDLER_CONTENT_DIR, 'www/')
        basehttphandler.__init__(self,  *args)
        
    def do_GET(self):
        if self.req_path.startswith('/payload/'):
            m = re.search(r"\/payload\/(\d+)", self.req_path)
            payloadindex = m.group(1)
            content = self._payload(payloadindex)
            self.send_http_response(200, content)
        elif self.req_path.endswith('/'):
            if self.dir_browsing is True:
                self.send_http_response(200, self._dir_browsing(self.req_path))
            else:
                content = self._get_file(self.req_path + 'index.html')
                if content is not None:
                    self.send_http_response(200, content)
                else:
                    self.send_error(404)
        else:
            content = self._get_file(self.req_path)
            if content is not None:
                self.send_http_response(200, content)
            else:
                self.send_error(404)
        
    def _get_file(self, file):
        '''
        Load files from the resource directory
        '''
        try:
            file = os.path.abspath('/' + file).lstrip('/')
            path = os.path.join(self.www_root, file)
            self.debug("HTTP request for static file {}".format(path))
            file = open(path, "r")
            return file.read()
        except:
            pass
        return None
    
    def _dir_browsing(self, path):
        dir = os.path.join(self.www_root, os.path.abspath('/' + path).lstrip('/'))
        
        d = path.replace(self.www_root, "")
        page = self.DIR_INDEX_PAGE.replace("$BASEDIR$", os.path.join(path, '..').replace(self.www_root, ""))
        if not d:
            d = "/"
            page = page.replace("$BASEDIR$", "/")

        page = page.replace("$DIR$", d)
        
        filelist = ""
        for item in os.listdir(dir):
            link = os.path.join(path, item)
            if os.path.isdir(os.path.join(dir, item)):
                link = link + '/'
            filelist = filelist + '<tr><td><a href='+link+'>'+item+'</a></td></tr>\n'
        page = page.replace("$FILELIST$", filelist)
        return page
    
    def _payload(self, index):
        resp = None
        try:
            with open(self.payloadfile, 'r') as f:
                resp = f.readlines()[int(index)-1]
        except:
            self.debug("Failed to load payload or index")
        return resp
                
