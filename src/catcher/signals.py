from django.db.models.signals import post_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from catcher.models import Callback, Fingerprint

import base64
import logging
import binascii

logger = logging.getLogger(__name__)

@receiver(post_save, sender=Callback)
def detect_fingerprint(sender, instance, created, **kwargs):
    """
    Runs after saving to Callback model
    Adds a fingerprint to the entry
    """
    callback = instance

    if callback.fingerprint is None:
        try:
            data = callback.data
            for f in Fingerprint.objects.all():
                try:
                    raw = base64.b64decode(f.probe).decode('unicode-escape')
                    probe = "".join([hex(ord(c))[2:].zfill(2) for c in raw])
                    #if req in data.encode('hex')[:len(probe)]:
                    if probe in binascii.hexlify(data)[:len(probe)]:
                        callback.fingerprint = f
                        callback.save()
                        logger.info("Request recognised as {}".format(f.name))
                        break
                except:
                    pass
        except Exception as e:
            logger.error(e)