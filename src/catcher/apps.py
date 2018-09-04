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
        from catcher.models import Port, Fingerprint
        from catcher.service import Service
        
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
        process = Service(settings.LISTEN_IP, 8000, 'tcp', 0)
        process.set_handler('static_http.py')
        process.start()
        
        process = Service(settings.LISTEN_IP, 53, 'udp', 0)
        process.set_handler('dns.py')
        process.start()
        
        #process = Service(settings.LISTEN_IP, 443, 'tcp', 1)
        #process.set_handler('static_http.py')
        #process.start()
        
        process = Service(settings.LISTEN_IP, 21, 'tcp', 0)
        process.set_handler('ftp.py')
        process.start()
        
        
    