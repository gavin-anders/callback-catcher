from django.apps import AppConfig

class CatcherConfig(AppConfig):
    name = 'catcher'
    verbose_name = 'CallBack Catcher'
 
    def ready(self):
        from django.contrib.auth.models import User
        from catcher.models import Port, Fingerprint, Port, Handler
        from catcher.service import Service
        from catcher.config import CatcherConfigParser
        
        import catcher.signals
        import catcher.settings as settings
        
        import socket
        import logging
        import xml.etree.ElementTree as ET
        import multiprocessing
        import os
        import sys
        import importlib
        
        logger = logging.getLogger(__name__)
        
        print(settings.BANNER)
        
        #Drop all the users and add one user to rule them all
        logger.info("Setting up users")
        User.objects.all().delete() 
        user = User.objects.create_user(username=settings.USERNAME, 
                                        email=settings.EMAIL, 
                                        password=settings.PASSWORD)
        
        #Adds fingerprints
        logger.info("Loading fingerprints")
        try:
            tree = ET.parse(settings.FINGERPRINT_DEFS)
            for fingerprint in tree.getroot():
                name = fingerprint.find("name").text
                probe = fingerprint.find("probe").text
                obj, created = Fingerprint.objects.get_or_create(
                    name=name,
                    defaults={'name': name, 'probe': probe},
                )
        except:
            logger.error("Unable to load {}".format(settings.FINGERPRINT_DEFS))
            #raise
        logger.info("Fingerprints loaded successfully")
        
        #Add handlers to database
        logger.info("Importing handlers")
        exclude_handlers = ('__init__.py', 'basehandler.py')
        try:
            handler_count = 0
            for filename in os.listdir(settings.HANDLER_DIR):
                if filename.endswith(".py") and filename not in exclude_handlers: 
                    try:
                        handlername, ext = filename.split(".", 1)
                        plugin = importlib.import_module('catcher.handlers.' + handlername)
                        handler = getattr(plugin, handlername)
                                                
                        description = ""
                        if hasattr(handler, 'NAME') and hasattr(handler, 'DESCRIPTION'):
                            handlername = handler.NAME
                            handlerdesc = handler.DESCRIPTION
                            #Parse any settings that the handler may have
                            defaults={'name': handlername, 'filename': filename, 'description': handlerdesc, 'settings': {}}
                            c = CatcherConfigParser(defaults=settings.DEFAULT_HANDLER_SETTINGS)
                            if hasattr(handler, 'SETTINGS'):
                                logger.debug("{}: Found custom settings. Updating db.".format(filename))
                                for i, v in getattr(handler, 'SETTINGS').items():
                                    c.add_setting(i, v)
                                    
                            defaults['settings'] = c.get_settings(json_format=True)
                            handlerobj, created = Handler.objects.update_or_create(
                                name=handlername,
                                defaults=defaults,
                            )
                            handler_count = handler_count + 1
                        else:
                            raise AttributeError
                        logger.info("{}: Imported".format(filename))
                    except ImportError:
                        logger.error("{}: Import failed. Skipping".format(filename))
                    except AttributeError:
                        logger.error("{}: Import failed. Handler missing attribute. Skipping...".format(filename))
                    except Exception as e:
                        raise
                        logger.exception("{}: Unknown error whilst importing. {}".format(filename, e))
                        sys.exit()
        except:
            logger.exception("Unable to load handlers")
            raise
        logger.info("{} handlers loaded successfully".format(handler_count))
        
        #Check if any ports are reported as running in the db and remove
        logger.info("Cleaning up database")
        ports = Port.objects.all()
        for p in ports:
            p.delete()
        
        #TESTING start services
        for p in settings.DEFAULT_PORTS:
            try:
                process = Service(settings.LISTEN_IP, p['port'], p['protocol'], p['ssl'])
                process.set_handler(p['handler'])
                if p['ssl'] is 1:
                    process.set_ssl_context(settings.SSL_CERT, settings.SSL_KEY)
                process.start()
                handler = Handler.objects.get(filename=p['handler'])
                pobj = Port.objects.create(number=process.number, protocol=process.protocol, ssl=process.ssl, handler=handler, pid=process.pid)
            except Exception as e:
                logger.error("Failed to start process")
                logger.exception(e)
                #raise
        
        
    