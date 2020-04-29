from django.apps import AppConfig
import signal
import sys
import inspect

def keyboard_signal_handler(signal, frame):
    print("Killing processes...")
    sys.exit(0)

class CatcherConfig(AppConfig):
    name = 'catcher'
    verbose_name = 'CallBack Catcher'
    
    def check_python_version(self):
        if sys.version_info[0] < 3:
            raise Exception("ERROR: Try using Python 3")
    
    def ready(self):
        self.check_python_version()
        #check command arguments
        if "manage.py" in sys.argv and "runserver" in sys.argv:
            self.pre_run()
            pass
 
    def pre_run(self):
        #from django.contrib.auth.models import User
        from catcher.models import Port, Port, Handler, Client
        from catcher.config import CatcherConfigParser
        from catcher.utils import is_process_running
        import catcher.signals
        import catcher.settings as settings
        
        from django.contrib.auth.models import Group, Permission
        
        import socket
        import logging
        import multiprocessing
        import os
        import sys
        import importlib
        import time
        
        logger = logging.getLogger(__name__)
        
        print(settings.BANNER)
        
        #Drop all the users and add one user to rule them all
        logger.info("Setting up users")
        clientgroup, created = Group.objects.get_or_create(name='clients')
        Client.objects.filter(username=settings.USERNAME).delete() 
        user = Client.objects.create_superuser(username=settings.USERNAME, 
                                               email=settings.USERNAME + "@catcher.com", 
                                               password=settings.PASSWORD,
                                               is_staff=True,
                                               is_superuser=True)
        user.groups.add(clientgroup)    #add the user to the group
        client_permissions = Permission.objects.filter(codename__in=settings.CLIENT_USER_PERMISSIONS)
        for p in client_permissions:
            clientgroup.permissions.add(p)        
        
