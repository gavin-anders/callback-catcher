from django.apps import AppConfig

class CatcherConfig(AppConfig):
    name = 'catcher'
    verbose_name = 'CallBackCatcher Client'
 
    def ready(self):
        import socket
        import logging
        import catcher.signals
        import catcher.settings as settings
        from catcher.models import Port
        from catcher.service import Service
        
        logger = logging.getLogger(__name__)
        
        #Check if any ports are reported as running in the db and remove
        ports = Port.objects.all()
        for p in ports:
            server_address = (settings.LISTEN_IP, p.number)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if p.protocol == 'udp':
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                sock.bind(server_address)
                logger.info("Removing {} entry from DB".format(p))
                p.delete()
            except:
                pass
            finally:
                sock.close()
        
        #TESTING start services
        #process = Service(settings.LISTEN_IP, 80, 'tcp', 0)
        #process.set_handler('static_http.py')
        #process.start()
        
        #process = Service(settings.LISTEN_IP, 443, 'tcp', 1)
        #process.set_handler('static_http.py')
        #process.start()
        
        #process = Service(settings.LISTEN_IP, 21, 'tcp', 0)
        #process.set_handler('ftp.py')
        #process.start()
        
        #process = Service(settings.LISTEN_IP, 53, 'udp', 0)
        #process.set_handler('dns.py')
        #process.start()
    