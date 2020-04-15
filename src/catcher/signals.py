from django.dispatch import receiver
from django.contrib.auth.models import User
from django.conf import settings
from django.db.models.signals import post_save

from catcher.models import Callback, Fingerprint, Token
from catcher.settings import TOKEN_QUEUE, FINGERPRINT_QUEUE, ADVANCED_TOKEN_DETECTION

import base64
import logging
import binascii
import queue
import threading
import urllib

logger = logging.getLogger(__name__)

def token_detect_worker():
    while True:
        job = TOKEN_QUEUE.get()
        if job is None:
            break
        
        tokens, callback = job
        #consider a more advanced method of detection other than raw string search
        for t in tokens:
            searches = []
            searches.append(str.encode(t.token))
            if ADVANCED_TOKEN_DETECTION == True:
                rawtoken = t.token.encode()
                hextoken = binascii.hexlify(rawtoken)
                searches.append(hextoken) #hex encoded
                searches.append(binascii.b2a_base64(rawtoken)) #base64 encoded
                urlencodedtoken = ""
                for i in range(0, len(hextoken), 2):
                    urlencodedtoken = urlencodedtoken + "%{}".format(hextoken[i:i+2].decode("utf-8")) 
                searches.append(str.encode(urlencodedtoken)) #url encoded
            
            #if raw_token in callback.data:
            if any(t in callback.data for t in searches):
                logger.info("Found token in callback {}".format(callback.id))
                t.callback = callback
                t.save()
                break
        TOKEN_QUEUE.task_done()
        
def fingerprint_detect_worker():
    while True:
        job = FINGERPRINT_QUEUE.get()
        if job is None:
            break
        
        fingerprints, callback = job
        for f in fingerprints:
            try:
                raw = base64.b64decode(f.probe).decode('unicode-escape')
                probe = "".join([hex(ord(c))[2:].zfill(2) for c in raw])
                if probe in binascii.hexlify(data)[:len(probe)]:
                    callback.fingerprint = f
                    callback.save()
                    logger.info("Request recognised as {}".format(f.name))
                    break
            except:
                pass
        FINGERPRINT_QUEUE.task_done()

@receiver(post_save, sender=Callback)
def detect_fingerprint(sender, instance, created, **kwargs):
    """
    Runs after saving to Catcher model
    Adds a fingerprint to the entry
    """
    if instance.fingerprint is None:
        fingerprints = Fingerprint.objects.all()
        item = [fingerprints, instance,]
        FINGERPRINT_QUEUE.put(item)
        thread = threading.Thread(target=fingerprint_detect_worker,)
        thread.start()
            
@receiver(post_save, sender=Callback)
def detect_token(sender, instance, created, **kwargs):
    """
    Runs after saving to Callback model
    Checks if token within callback data
    """
    tokens = Token.objects.all()
    item = [tokens, instance,]
    TOKEN_QUEUE.put(item)
    thread = threading.Thread(target=token_detect_worker,)
    thread.start()
            
