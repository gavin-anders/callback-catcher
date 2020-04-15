'''
Inspiration and base code taken from https://github.com/letsencrypt/boulder/blob/ba1fb8b3c3ed86a57f0636ae05d30629bd31e496/test/chisel2.py
'''

from django.core.management.base import BaseCommand

import re
import sys
import os
import time
from contextlib import contextmanager

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509

from OpenSSL import crypto
import josepy
import acme
import logging

from acme import challenges
from acme import client as acme_client
from acme import crypto_util as acme_crypto_util
from acme import errors as acme_errors
from acme import messages

from dnslib import RR, QTYPE, RCODE, TXT, A
from dnslib.server import DNSServer, DNSHandler, BaseResolver, DNSLogger

from catcher.settings import SSL_KEY, SSL_CERT, FILES_DIR, DOMAIN, EMAIL, EXTERNAL_IP, LETSENCRYPTDIRECTORY

logging.disable(logging.CRITICAL)

TXTRECORDS = []
LETSENCRYPTDIRECTORY = "https://acme-staging-v02.api.letsencrypt.org/directory"

class Command(BaseCommand):
    help = 'Creates certificates and keys for services supporting SSL'

    def add_arguments(self, parser):
        parser.add_argument('--domain', type=str, default=DOMAIN, help='Extra domains the catcher will be hosted on')

    def handle(self, *args, **kwargs):
        try:
            d = "*." + DOMAIN
            domains = list(set([d, DOMAIN, kwargs['domain'],]))
            letsencryptkey = os.path.join(FILES_DIR, 'ssl/account.pem')
            servercertpath = os.path.join(FILES_DIR, 'ssl/server.crt')
            serverkeypath = os.path.join(FILES_DIR, 'ssl/server.key')
    
            sys.stdout.write("[+] Writting to: {}\n".format(FILES_DIR))

            self.start_verify_server(EXTERNAL_IP)
            TXTRECORDS.append("test123")
    
            client = self.create_acme_client(EMAIL)
            
            #Generate csr
            sys.stdout.write("[+] Generating server csr\t")
            serverkey = self.gen_key()
            pem = crypto.dump_privatekey(crypto.FILETYPE_PEM, serverkey)
            with open(serverkeypath, 'w') as f:
                f.write(pem.decode('utf-8'))
            csr = acme_crypto_util.make_csr(pem, domains, False)
            sys.stdout.write("OK!\n")
            
            sys.stdout.write("[+] Generating server cert\t")
            order = client.new_order(csr)
            
            for a in order.authorizations:
                c = self.get_challenge(a, challenges.DNS01)
                name, value = (c.validation_domain_name(a.body.identifier.value), c.validation(client.net.key))
                TXTRECORDS.append(value)
                client.answer_challenge(c, c.response(client.net.key))
           
            print(TXTRECORDS)
            order = client.poll_and_finalize(order)
            print(order)
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, order.fullchain_pem)
            with open(servercertpath, 'w') as file:
                print("writting file")
                file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert).decode('utf-8'))
            sys.stdout.write("OK!\n")
                
            sys.stdout.write("[+] Successfully signed certificate for '{}'\n".format(d))
            sys.stdout.write("[+] Certificate and keys can be found under {}\n".format(os.path.join(FILES_DIR, 'ssl/')))
        except acme.errors.ValidationError as e:
            raise
            sys.stdout.write("FAILED!\n")

    def start_verify_server(self, resolveip):
        resolver = LetsEncryptResolver(resolveip)
        logger = EmptyLogger()
        udp_server = DNSServer(resolver, port=53, address='0.0.0.0', logger=logger)
        udp_server.start_thread()
        sys.stdout.write("[+] DNS server\t\t\tSTARTED\n")

    def create_acme_client(self, email=None):
        key = josepy.JWKRSA(key=rsa.generate_private_key(65537, 2048, default_backend()))
        net = acme_client.ClientNetwork(key, user_agent="Callback Catcher Client")
        directory = messages.Directory.from_json(net.get(LETSENCRYPTDIRECTORY).json())
        client = acme_client.ClientV2(directory, net)
        tos = client.directory.meta.terms_of_service
        client.net.account = client.new_account(messages.NewRegistration.from_data(email=email, terms_of_service_agreed=True))
        return client
    
    def gen_key(self):
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)
        return key
    
    def get_challenge(self, authz, typ):
        for chall_body in authz.body.challenges:
            if isinstance(chall_body.chall, typ):
                return chall_body
        raise Exception("No %s challenge found" % typ.typ)

    def do_dns_challenges(self, client, authzs):
        for a in authzs:
            c = self.get_challenge(a, challenges.DNS01)
            name, value = (c.validation_domain_name(a.body.identifier.value), c.validation(client.net.key))
            TXTRECORDS.append(value)
            sys.stdout.write("[+] Adding DNS TXT record to server\n")
            client.answer_challenge(c, c.response(client.net.key))

class LetsEncryptResolver(BaseResolver):
    def __init__(self, ip):
        self.ip = ip

    def resolve(self, request, handler):
        reply = request.reply()
        qname = request.q.qname
        reply.add_answer(RR(qname, QTYPE.A, ttl=60, rdata=A(self.ip)))
        if "_acme-challenge" in str(qname).lower():
            for x in TXTRECORDS:
                reply.add_answer(RR(qname, QTYPE.TXT, rdata=TXT(x.strip())))
        return reply

class EmptyLogger(DNSLogger):
    def __init__(self,log="",prefix=True): pass
    def log_pass(self, *args): pass
    def log_prefix(self, *args): pass
    def log_recv(self, *args): pass
    def log_send(self, *args): pass
    def log_request(self, *args): pass
    def log_reply(self, *args): pass
    def log_truncated(self, *args): pass
    def log_error(self, *args): pass
    def log_data(self, *args): pass
