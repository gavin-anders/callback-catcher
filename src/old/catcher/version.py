'''
Created on 11 Dec 2017

@author: gavin
'''
from socket import gethostname

# Version number (float)
catcher_version = 0.1
machine_name = gethostname()
catcher_banner = 'Catcher %s (%s)' % (catcher_version, machine_name)