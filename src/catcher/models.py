from django.db import models
from django.contrib.auth.models import User
from django_extensions.db.fields.encrypted import EncryptedCharField
from django.core.validators import MaxValueValidator, MinValueValidator
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import User
from django.utils import timezone
from jsonfield import JSONField
import datetime
import base64
import binascii
import hashlib
import os
import uuid

def _expire_days(days=30):
    return timezone.now() + datetime.timedelta(days=days)

def _gen_token_hash():
    rand = os.urandom(32)
    hash = hashlib.md5(rand).hexdigest()
    return hash

class Callback(models.Model):
    id          = models.AutoField(primary_key=True)
    sourceip    = models.GenericIPAddressField()
    sourceport  = models.IntegerField(default=0)
    serverip    = models.GenericIPAddressField()
    serverport  = models.IntegerField()
    protocol    = models.CharField(max_length=3, default="tcp")
    timestamp   = models.DateTimeField(auto_now_add=True)
    datasize    = models.IntegerField()
    datahex     = models.TextField(null=True)
    data        = models.BinaryField()
    fingerprint = models.ForeignKey('Fingerprint', null=True, on_delete=models.DO_NOTHING)
    
    class Meta:
        db_table = 'callback'
        
    @classmethod
    def create(cls, sourceip, sourceport, serverip, serverport, protocol, data):
        callback = cls(sourceip=sourceip,
                       sourceport=sourceport,
                       serverip=serverip,
                       serverport=serverport,
                       protocol=protocol,
                       data=data
                       )
        return callback
    
    def save(self, *args, **kwargs):
        self.datasize = len(self.data)
        self.datahex = binascii.hexlify(self.data).decode()
        super().save(*args, **kwargs)
        
    def __str__(self):
        return "%i: %s/%s (%s)" % (self.id, self.sourceip, self.serverport, self.protocol)

class Port(models.Model):
    id            = models.AutoField(primary_key=True)
    number        = models.IntegerField(validators=[MaxValueValidator(65535), MinValueValidator(1)])
    protocol      = models.CharField(max_length=3, null=False)
    ssl           = models.IntegerField()
    created_time  = models.DateTimeField(auto_now_add=True)
    pid           = models.IntegerField(null=True)
    handler       = models.ForeignKey('Handler', null=True, on_delete=models.DO_NOTHING)
    config        = JSONField(null=True) 
        
    class Meta:
        db_table = 'ports'
        unique_together = ('number', 'protocol')
        
    def __unicode__(self):
        return "%s/%s" % (self.number, self.protocol)

class Handler(models.Model):
    id              = models.AutoField(primary_key=True)
    name            = models.CharField(max_length=100)
    description     = models.TextField()
    filename        = models.CharField(max_length=200, null=False)
    default_config  = JSONField(null=True)
    
    class Meta:
        db_table = 'handlers'
        
    def __unicode__(self):
        return self.filename
    
class Fingerprint(models.Model):
    id         = models.AutoField(primary_key=True)
    name       = models.CharField(max_length=50, null=False)
    probe      = models.TextField(null=False)
    
    class Meta:
        db_table = 'fingerprints'
        
    def __unicode__(self):
        return self.name
    
    def __str__(self):
        return self.name
    

class Secret(models.Model):
    id          = models.AutoField(primary_key=True)
    name        = models.CharField(max_length=150, null=False)
    value       = models.TextField(null=False)
    callback    = models.ForeignKey('Callback', null=True, related_name='secrets', on_delete=models.SET_NULL)
    
    class Meta:
        db_table = 'secrets'
        
        
class Blacklist(models.Model):
    id = models.AutoField(primary_key=True)
    ip = models.GenericIPAddressField()

    class Meta:
        db_table = 'blacklist'
        
    def __unicode__(self):
        return self.ip
        
class Token(models.Model):
    id              = models.AutoField(primary_key=True)
    token           = models.CharField(max_length=100, default=_gen_token_hash, null=False, unique=True)
    created_time    = models.DateTimeField(auto_now_add=True)
    expire_time     = models.DateTimeField(default=_expire_days(30))
    client          = models.ForeignKey('Client', null=True, on_delete=models.SET_NULL)
    callback        = models.ForeignKey('Callback', null=True, on_delete=models.SET_NULL, related_name='tokencallback')

    class Meta:
        db_table = 'token'
        
    def __unicode__(self):
        return self.token
    
    def __str__(self):
        return self.token 
        
    
#class Client(models.Model):
#    id              = models.UUIDField(primary_key=True, default=uuid.uuid4)
#    name            = models.CharField(max_length=100, null=True)
#    email           = models.EmailField(max_length=100, null=True)
#    agent           = models.EmailField(max_length=200, null=True)
#    source          = models.GenericIPAddressField(default=None, null=True)
#    created_time    = models.DateTimeField(auto_now=True)
#    update_time     = models.DateTimeField(auto_now=True)
#    
#    class Meta:
#        db_table = 'client'
#        
#    def __unicode__(self):
#        return self.id
    
class ClientUserManager(BaseUserManager):
    use_in_migrations = True

    def create_user(self, username, email, **extra_fields):
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_unusable_password()
        user.save()
        return user

    def create_superuser(self, username, email, password, **extra_fields):
        email = self.normalize_email(email)
        user = self.model(username=username, email=email, is_staff=True, is_superuser=True)
        user.set_password(password)
        user.save()
        return user
    
class Client(AbstractBaseUser, PermissionsMixin):
    apikey          = models.UUIDField(unique=True, default=uuid.uuid4)
    username        = models.CharField(unique=True, max_length=100, null=False)
    name            = models.CharField(max_length=100, null=True)
    email           = models.EmailField(max_length=100, null=False)
    agent           = models.EmailField(max_length=200, null=True)
    source          = models.GenericIPAddressField(default=None, null=True)
    created_time    = models.DateTimeField(auto_now=True)
    update_time     = models.DateTimeField(auto_now=True)
    is_staff        = models.BooleanField(default=False)
    is_superuser    = models.BooleanField(default=False)
    is_client       = models.BooleanField(default=True)
    # use set_unusable_password() to ignore passwords when creating a client user
    
    objects = ClientUserManager()

    USERNAME_FIELD = 'username'
    REQUIRED_FIELDS = ['name', 'email']
    
    class Meta:
        db_table = 'clientuser'
        
        def __unicode__(self):
            return self.id
    