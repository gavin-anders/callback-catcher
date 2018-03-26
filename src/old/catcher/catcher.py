'''
Created on 11 Dec 2017

@author: gavin
'''
import logging
import multiprocessing
import webserver
import version
import utils
import sys
import os

from config import config as CONFIG
from logging.handlers import RotatingFileHandler
from catcherlogger import CatcherLogHandler

logger = None

class Catcher(object):
    """
    Main class for catcher
    """    
    def __init__(self):
        '''
        Constructor
        '''
        self.stdin_path = "/dev/null"
        self.stdout_path = CONFIG.stdout
        self.stderr_path = CONFIG.stderr
        self.pidfile_path = CONFIG.pidfile
        self.pidfile_timeout = CONFIG.pidtimeout
        
    def clean_up_processes(self):
        '''
        Run on exit of application
        '''
        try:
            for p in multiprocessing.active_children():
                p.terminate()
        except Exception, e:
            logging.exception(e)
            
    def setup_logging(self, name, location, size, backup):
        """
        Enables the logging for the entire daemon
        """
        logger = logging.getLogger(name)
        logger.setLevel(logging.DEBUG)
        
        #Basic logging for non-process stuff
        daemonhandler = RotatingFileHandler(location, maxBytes=size, backupCount=backup)
        daemonhandler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        daemonhandler.setFormatter(formatter)
        logger.addHandler(daemonhandler)
        
        #Process logging, sends back to main server
        serverlogger = CatcherLogHandler(CONFIG.serverurl, CONFIG.identifier, (CONFIG.serveruser, CONFIG.serverpass))
        logger.addHandler(serverlogger)
        return logger
            
    def start_webserver(self, host, ip, user, password, sslcert, sslkey):
        '''
        Starts web server in seperate process
        webserver functions abstracted into webserver.py
        '''
        try:
            webserver.run(host, ip, user, password, sslcert, sslkey)
            logger.info("Started web server on https://%s:%s/" % (host, ip)) 
        except Exception, e:
            logging.exception(e)
            sys.exit()

    def run(self):
        #Set up logging
        global logger
        logger = self.setup_logging('catcher', CONFIG.logfile, CONFIG.logsize, CONFIG.logrotate) 
        logger.info("Starting %s" % version.catcher_banner)
        
        #Start web server
        self.start_webserver(
                        CONFIG.apiip, 
                        CONFIG.apiport, 
                        CONFIG.sslcert,
                        CONFIG.sslkey,
                        CONFIG.apiuser, 
                        CONFIG.apipass)
        
if __name__ == '__main__':
    print "Started"
    c = Catcher()
    c.run()
        
