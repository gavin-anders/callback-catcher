'''
Created on 10 Dec 2017

@author: gavin
'''
from ConfigParser import ConfigParser, Error
import sys
import os

class Config(object):
    '''
    Holds and sorts the configuration variables.
    '''
    CONFGIFILE    = '/opt/catcher/config.ini'
    RESOURCE_DIR  = 'resources'
    HANDLER_DIR   = 'handlers'
    PID_DIR       = 'run'
    LOG_DIR       = 'logs'
    PID_FILE_NAME = 'catcher.pid'
    LOG_FILE_NAME = 'debug.log'
    
    def __init__(self):
        '''
        Load the config from the specified ini file. 
        '''
        filename = './config.ini'
        if not os.path.isfile(filename):
            filename = Config.CONFGIFILE
            print "Using config: %s" % filename
        
        try:
            config = ConfigParser()
            config.read(filename)
            
            #Variables
            self.listenip     = config.get('Catcher', 'listen')
            self.identifier   = config.get('Catcher', 'identifier')
            
            self.apiip        = config.get('API', 'ip')
            self.apiport      = int(config.get('API', 'port'))
            self.apiuser      = config.get('API', 'user')
            self.apipass      = config.get('API', 'password')
            
            self.serverip     = config.get('Server', 'ip')
            self.serverport   = int(config.get('Server', 'port'))  
            self.serveruser   = config.get('Server', 'user')
            self.serverpass   = config.get('Server', 'password')

            if int(config.get('Server', 'ssl')) == 1:
                self.serverurl  = "https://%s:%i" % (self.serverip, self.serverport)
            else:
                self.serverurl  = "http://%s:%i" % (self.serverip, self.serverport)
                    
            self.giturl       = config.get('Handlers', 'git_url')
               
            self.runlocation  = config.get('Daemon', 'run_location')     
            self.pidtimeout   = int(config.get('Daemon', 'pidtimeout'))
            self.stdout       = config.get('Daemon', 'stdout')
            self.stderr       = config.get('Daemon', 'stderr')
            
            self.logsize      = config.get('Debugging', 'Size')
            self.logrotate    = int(config.get('Debugging', 'Rotate'))

            #Directorties
            self.loglocation  = str(os.path.join(self.runlocation, Config.LOG_DIR))
            self.pidlocation  = str(os.path.join(self.runlocation, Config.PID_DIR))
            self.handlerdir   = str(os.path.join(self.runlocation, Config.HANDLER_DIR))
            self.resourcedir  = str(os.path.join(self.runlocation, Config.RESOURCE_DIR))
            
            #Files
            self.pidfile      = str(os.path.join(self.pidlocation, Config.PID_FILE_NAME))
            self.logfile      = str(os.path.join(self.loglocation, Config.LOG_FILE_NAME))
            self.sslcert      = str(os.path.join(self.resourcedir, config.get('Files', 'cert')))
            self.sslkey       = str(os.path.join(self.resourcedir, config.get('Files', 'certkey')))
            
            self.validate()
        except Exception, e:
            print "[-] Config not loaded: %s" % e
            sys.exit()
    
    def validate(self):
        '''
        validates the given config file
        '''
        cwd = os.getcwd()
        #check directories
        dirs = (self.runlocation, self.loglocation, self.pidlocation, self.handlerdir, self.resourcedir) #runlocation needs to be first
        for d in dirs:
            if not os.path.exists(d):
                os.makedirs(d)
        
        if not os.path.exists(os.path.join(cwd, self.sslcert)):
            raise Error('%s file not found' % self.sslcert)
        if not os.path.exists(os.path.join(cwd, self.sslkey)):
            raise Error('%s file not found' % self.sslkey)
        if not os.path.exists(os.path.join(cwd, self.loglocation)):
            open(self.loglocation, 'a').close()
            
config = Config()