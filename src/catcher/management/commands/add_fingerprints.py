from django.core.management.base import BaseCommand
from catcher.settings import FINGERPRINT_DEFS
from catcher.models import Fingerprint

import os
import sys
import xml.etree.ElementTree as ET

class Command(BaseCommand):
    help = 'Populates the fingerprint table with pre-defined list'
    
    def add_arguments(self, parser):
        parser.add_argument('--fingerprintdir', type=str, default=FINGERPRINT_DEFS, help='Fingerprint file location')

    def handle(self, *args, **kwargs):
        fingerprintfile = kwargs['fingerprintdir']
        
        try:
            if not os.path.exists(fingerprintfile):
                sys.stdout.write("[-] {} not found\n".format(fingerprintfile))
                raise

            tree = ET.parse(fingerprintfile)
            for fingerprint in tree.getroot():
                name = fingerprint.find("name").text
                probe = fingerprint.find("probe").text
                obj, created = Fingerprint.objects.get_or_create(
                    name=name,
                    defaults={'name': name, 'probe': probe}
                )
                sys.stdout.write("[+] '{}' fingerprint added\n".format(name))
        except:
            sys.stdout.write("[-] Failed adding fingerprints\n")
        
   