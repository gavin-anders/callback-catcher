from django.apps import AppConfig

class CatcherConfig(AppConfig):
    name = 'catcher'
    verbose_name = 'CallBackCatcher Client'
 
    def ready(self):
        import socket
        import logging
        import xml.etree.ElementTree as ET
        import catcher.signals
        import catcher.settings as settings
        from catcher.models import Port, Fingerprint, Port, Handler
        from catcher.service import Service
        import multiprocessing
        
        logger = logging.getLogger(__name__)
        
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
            raise
        logger.info("Fingerprints loaded successfully")
        
        #Check if any ports are reported as running in the db and remove
        logger.info("Cleaning up database")
        ports = Port.objects.all()
        for p in ports:
            p.delete()
        
        #TESTING start services
        try:
            for p in settings.DEFAULT_PORTS:
                process = Service(settings.LISTEN_IP, p['port'], p['protocol'], p['ssl'])
                process.set_handler(p['handler'])
                process.start()
                handler = Handler.objects.get(filename=p['handler'])
                Port.objects.create(number=process.number, protocol=process.protocol, ssl=process.ssl, handler=handler, pid=process.pid)
        except Exception as e:
            logger.error("Failed to start process")
            logger.exception(e)
            raise
        
        
    