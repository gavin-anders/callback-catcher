
from django.db import models
from django.contrib.auth.models import User
from django_extensions.db.fields.encrypted import EncryptedCharField
from django.core.validators import MaxValueValidator, MinValueValidator
import base64
import binascii

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

class Port(models.Model):
    id            = models.AutoField(primary_key=True)
    number        = models.IntegerField(validators=[MaxValueValidator(65535), MinValueValidator(1)])
    protocol      = models.CharField(max_length=3, null=False)
    ssl           = models.IntegerField()
    created_time  = models.DateTimeField(auto_now_add=True)
    pid           = models.IntegerField(null=True)
    handler       = models.ForeignKey('Handler', null=True, on_delete=models.DO_NOTHING)
        
    class Meta:
        db_table = 'ports'
        unique_together = ('number', 'protocol')
        
    def __unicode__(self):
        return "%s/%s" % (self.number, self.protocol)
        

class Handler(models.Model):
    id           = models.AutoField(primary_key=True)
    name         = models.CharField(max_length=100)
    description  = models.TextField()
    filename     = models.CharField(max_length=200, null=False)
    settings     = models.TextField(null=True) #might need to be a relationship
    
    class Meta:
        db_table = 'handlers'
        
    def __unicode__(self):
        return self.filename
    
class Fingerprint(models.Model):
    id         = models.AutoField(primary_key=True)
    name       = models.CharField(max_length=50, null=False)
    probe      = models.CharField(max_length=100, null=False)
    
    class Meta:
        db_table = 'fingerprints'
        
    def __unicode__(self):
        return self.name
    

class Secret(models.Model):
    id          = models.AutoField(primary_key=True)
    name        = models.CharField(max_length=150, null=False)
    value       = models.TextField(null=False)
    callback    = models.ForeignKey('Callback', null=True, related_name='secrets', on_delete=models.SET_NULL)
    
    class Meta:
        db_table = 'secrets'
        
        
class Token(models.Model):
    id          = models.AutoField(primary_key=True)
    name        = models.CharField(max_length=100, null=False)
    token       = models.CharField(max_length=250, null=False, unique=True)
    callback    = models.ForeignKey('Callback', related_name='tokens', null=True, on_delete=models.SET_NULL)
    
    class Meta:
        db_table = 'tokens'
        