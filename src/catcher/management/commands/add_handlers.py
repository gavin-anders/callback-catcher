from django.core.management.base import BaseCommand
from catcher.settings import HANDLER_DIR
from catcher.models import Handler
from catcher.config import CatcherConfigParser

import os
import sys
import importlib
import inspect

class Command(BaseCommand):
    help = 'Populates the fingerprint table with pre-defined list'
    
    def add_arguments(self, parser):
        parser.add_argument('--handlerdir', type=str, default=HANDLER_DIR, help='Handler file location')

    def handle(self, *args, **kwargs):
        handlerdir = kwargs['handlerdir']
        
        if not os.path.isdir(handlerdir):
            sys.stdout.write("[-] {} directory not found\n".format(handlerdir))
            raise

        sys.stdout.write("[+] Importing handlers")
        exclude_handlers = ('__init__.py', 'basehandler.py', 'packets.py')
        handler_count = 0
        try:
            for filename in os.listdir(handlerdir):
                if filename.endswith(".py") and filename not in exclude_handlers: 
                    try:
                        handlername, ext = filename.split(".", 1)
                        plugin = importlib.import_module('catcher.handlers.' + handlername)
                        handler = getattr(plugin, handlername)
                                                
                        description = ""
                        if hasattr(handler, 'NAME') and hasattr(handler, 'DESCRIPTION') and hasattr(handler, 'CONFIG'):
                            handlername = handler.NAME
                            handlerdesc = handler.DESCRIPTION
                            #Parse any config settings that the handler may have
                            defaults={'name': handlername, 'filename': filename, 'description': handlerdesc, 'default_config': {}}
                            c = CatcherConfigParser()
                            for cls in inspect.getmro(handler):
                                if hasattr(cls, 'CONFIG'):
                                    for i, v in getattr(cls, 'CONFIG').items():
                                        c.add_config(i, v)
                                    
                            defaults['default_config'] = c.get_config(json_format=True)
                            handlerobj, created = Handler.objects.update_or_create(
                                name=handlername,
                                defaults=defaults,
                            )
                            handler_count = handler_count + 1
                        else:
                            raise AttributeError
                        sys.stdout.write("\t[+] {}: Imported\n".format(filename))
                    except ImportError:
                        sys.stdout.write("\t[-] {}: Import failed. Skipping\n".format(filename))
                        raise
                    except AttributeError:
                        sys.stdout.write("\t[-] {}: Import failed. Handler missing attribute. Skipping...\n".format(filename))
                    except Exception as e:
                        sys.stdout.write("\t[-] {}: Unknown error whilst importing. {}".format(filename, e))
        except:
            sys.stdout.write("[-] Unable to load handlers\n")
        sys.stdout.write("[+] {} handlers loaded successfully\n".format(handler_count))
        sys.stdout.write("[+] Finished loading handlers\n")
        
   