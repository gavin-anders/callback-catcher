'''
Created on 12 Dec 2017

@author: gavin
'''
import logging
import os
import tarfile

from logging.handlers import RotatingFileHandler
from catcherlogger import CatcherLogHandler
from config import config as CONFIG

def setup_logging(name, location, size, backup):
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

