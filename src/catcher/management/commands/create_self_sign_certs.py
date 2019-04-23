from django.core.management.base import BaseCommand
from catcher.utils import *
from catcher.settings import SSL_KEY, SSL_CERT, FILES_DIR, DOMAIN
from OpenSSL import crypto
from OpenSSL import SSL

import sys
import hashlib
import sys
import string
import random

class Command(BaseCommand):
    help = 'Creates self seigned certificates and keys for services supporting SSL'
    
    def add_arguments(self, parser):
        parser.add_argument('--ca', type=str, default='CallBackCatcherCA', help='Certificate authority name')
        parser.add_argument('--domain', type=str, default=DOMAIN, help='Domain name catcher will be hosted on')

    def handle(self, *args, **kwargs):
        CA = kwargs['ca']
        CN = kwargs['domain']
        
        try:
            cakeypath = os.path.join(FILES_DIR, 'ssl/ca.key')
            cacertpath = os.path.join(FILES_DIR, 'ssl/ca.crt')
            self._create_ca(cakeypath, cacertpath, CA)
            CN = '*.{}'.format(CN)
            self._create_ssl_cert(cakeypath, cacertpath, CN)
            sys.stdout.write("[+] Successfully signed certificate for {}\n".format(CN))
            sys.stdout.write("[+] Certificates can be found under {}\n".format(os.path.join(FILES_DIR, 'ssl/')))
        except:
            sys.stdout.write("[-] Failed creating certificate")
        
    def _create_ca(self, privatekeypath, certpath, cn):
        '''
        Regenerates the key and relevent CA files
        '''
        try:       
            sys.stdout.write("[+] Generating CA key\t\t")
            key = self._gen_key()
            with open(privatekeypath, 'w') as file:
                file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))
            sys.stdout.write("OK!\n")
            
            csr = self._gen_cert_request(key, cn)
            
            sys.stdout.write("[+] Generating CA cert\t\t")
            cert = self._gen_cert(csr, csr, key, cn)
            with open(certpath, 'w') as file:
                file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
            sys.stdout.write("OK!\n")
        except Exception as e:
            sys.stdout.write("FAIL!\n")
            raise Exception('[-] Failed to write certs to ssl directory - {}'.format(str(e)))
        
    def _create_ssl_cert(self, cakeyfile, cacertfile, hostname):
        '''
        hostname is the CN to sign the cert
        keyfile is the private key
        cacert is the CA certificate
        
        return the newly created certificate path
        '''
        certpath = os.path.join(FILES_DIR, 'ssl/server.crt')
        keypath = os.path.join(FILES_DIR, 'ssl/server.key')
        
        sys.stdout.write("[+] Generating server key\t")
        key = self._gen_key()
        with open(keypath, 'w') as file:
            file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key).decode('utf-8'))
        sys.stdout.write("OK!\n")
            
        sys.stdout.write("[+] Generating server csr\t")
        csr = self._gen_cert_request(key, hostname)
        sys.stdout.write("OK!\n")
        
        #load ca key
        with open(cakeyfile, 'r') as file:
            cakey = crypto.load_privatekey(crypto.FILETYPE_PEM, file.read())
        
        #load ca cert
        with open(cacertfile, 'r') as file:
            cacert = crypto.load_certificate(crypto.FILETYPE_PEM, file.read())
        
        sys.stdout.write("[+] Generating server cert\t")
        cert = self._gen_cert(csr, cacert, cakey, hostname)
        with open(certpath, 'w') as file:
            file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
        sys.stdout.write("OK!\n")
        
        return keypath, certpath

        
    def _gen_key(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        return key
    
    def _gen_cert(self, csr, issuercert, issuerkey, cn): 
        #Generate unique serial
        md5_hash = hashlib.md5()
        rand = ''.join(random.choices(string.ascii_uppercase + string.digits, k=10))
        md5_hash.update(rand.encode())
        serial = int(md5_hash.hexdigest(), 36)
    
        cert = crypto.X509()
        cert.set_serial_number(serial)
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(10*365*24*60*60)
        cert.set_issuer(issuercert.get_subject())
        cert.set_subject(csr.get_subject())
        cert.set_pubkey(csr.get_pubkey())
        cert.sign(issuerkey, 'sha256')
        return cert
    
    def _gen_cert_request(self, key, cn):
        csr = crypto.X509Req()
        subj = csr.get_subject()
        setattr(subj, 'CN', cn)
        #add more fields here
        csr.set_pubkey(key)
        csr.sign(key, 'sha256')
        return csr


            