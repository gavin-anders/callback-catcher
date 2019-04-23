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
        signal.signal(signal.SIGINT, keyboard_signal_handler)
        self.check_python_version()
        #check command arguments
        if "manage.py" in sys.argv and "runserver" in sys.argv:
            self.pre_run()
            pass
 
    def pre_run(self):
        #from django.contrib.auth.models import User
        from catcher.models import Port, Port, Handler, Client
        from catcher.service import Service
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
                                               email=settings.EMAIL, 
                                               password=settings.PASSWORD,
                                               is_staff=True,
                                               is_superuser=True)
        user.groups.add(clientgroup)    #add the user to the group
        client_permissions = Permission.objects.filter(codename__in=settings.CLIENT_USER_PERMISSIONS)
        for p in client_permissions:
            clientgroup.permissions.add(p)
        
        #Check if any ports are reported as running in the db and remove
        logger.info("Cleaning up database")
        ports = Port.objects.all()
        for p in ports:
            p.delete()
        
        #Start default services
        for p in settings.DEFAULT_PORTS:
            try:
                process = Service(settings.LISTEN_IP, p['port'], p['protocol'], p['ssl'], ipv6=settings.IPV6)
                if p['ssl'] is 1:
                    process.set_ssl_context(settings.SSL_CERT, settings.SSL_KEY)
                handler = Handler.objects.get(filename=p['handler'])
                if handler:
                    process.set_handler(handler.filename)
                    parser = CatcherConfigParser()
                    parser.read(handler.default_config)
                    process.set_config(parser.get_config())
                    process.start()
                    if is_process_running(process.pid) is True:
                        pobj = Port.objects.create(number=process.number, 
                                                   protocol=process.protocol, 
                                                   ssl=process.ssl, 
                                                   handler=handler, 
                                                   pid=process.pid, 
                                                   config=handler.default_config)
                    else:
                        logger.info("Failed to start port")
                else:
                    logger.error("Unknown handler file in DEFAULT_PORTS. Ignoring.")              
            except Exception as e:
                if "Handler matching query does not exist" in str(e):
                    logger.error("Could not find handler filename in database. Check DEFAULT_PORTS")
                else:
                    logger.error("Failed to start process")
                    logger.exception(e)
                    raise
        
        