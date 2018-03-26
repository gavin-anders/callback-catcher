'''
Created on 16 Dec 2017

@author: gavin
'''
from logging.handlers import HTTPHandler
from communicator import Communicator
from datastructures import Log
import requests.exceptions

class CatcherLogHandler(HTTPHandler):
    '''
    Catcher own logger
    '''
    def __init__(self, url, identifier, credentials=None):
        """
        Inherit dont do anything here
        Inherited vars: method, url, host
        """
        HTTPHandler.__init__(self, "", "", method='POST')
        self.url = url
        self.username = credentials[0]
        self.password = credentials[1]
        self.identifier = identifier    #the UUID of the catcher, get from the config
    
    def pickle(self, record):
        '''
        recreates the dictionary to be passed off to communictor
        takes key values frpm orginal log message
        '''
        message = Log(record, self.identifier)
        return message.__dict__
    
    def emit(self, record):
        print "emit()"
        """
        Emit a record.
        Send the record to the Web server as a percent-encoded dictionary
        """
        logmsg = self.pickle(record)
        try:
            comm = Communicator(self.url, self.username, self.password)
            comm.send_log(logmsg)
        except (KeyboardInterrupt, SystemExit):
            raise
        except requests.exceptions.ConnectionError:
            print "Failed to send log to remote server"
        except:
            self.handleError(record)
        
if __name__ == "__main__":
    import logging
    logger = logging.getLogger('test')
    logger.setLevel(logging.DEBUG)
    handler = CatcherLogHandler(
                            'http://127.0.0.1:12443',
                            credentials=('root','Password1234')
                        )
    print handler.url
    logger.addHandler(handler)
    logger.info("this is a test")