from catcher.models import Client, Handler, Callback, Fingerprint, Port, Handler, Secret, Blacklist, Token
from django.contrib.auth.models import User
from rest_framework import serializers
from django.shortcuts import get_object_or_404
import pprint

class SecretSerializer(serializers.ModelSerializer):
    class Meta:
        model = Secret
        fields = ('id',
                  'name',
                  'value',
                  'callback'
                  )

class HandlerSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)
    description = serializers.CharField(read_only=True)
    filename = serializers.CharField(read_only=True)
    default_config = serializers.CharField(read_only=False)
    
    class Meta:
        model = Handler
        fields = ('id',
                  'name',
                  'description', 
                  'filename', 
                  'default_config')

class PortSerializer(serializers.ModelSerializer):
    handler = serializers.SlugRelatedField(many=False, required=False, queryset=Handler.objects.all(), slug_field='filename')

    class Meta:
        model = Port
        fields = ('id',
                  'number', 
                  'protocol', 
                  'ssl',  
                  'handler',
                  'config')
        
class CallbackSerializer(serializers.ModelSerializer):
    secrets = SecretSerializer(many=True, read_only=True)
    fingerprint = serializers.SlugRelatedField(many=False, read_only=True, slug_field='name')
    timestamp = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")

    class Meta:
        model = Callback
        fields = ('id',
                  'sourceip', 
                  'sourceport', 
                  'serverip', 
                  'serverport', 
                  'protocol',
                  #'data', - removed to avoid DoS
                  'datasize',
                  'fingerprint',
                  'secrets',
                  'timestamp'
                  )
        
class CallbackDetailSerializer(serializers.ModelSerializer):
    secrets = SecretSerializer(many=True, read_only=True)
    fingerprint = serializers.SlugRelatedField(many=False, read_only=True, slug_field='name')
    timestamp = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S")

    class Meta:
        model = Callback
        fields = ('id',
                  'sourceip', 
                  'sourceport', 
                  'serverip', 
                  'serverport', 
                  'protocol',
                  'data',
                  'datasize',
                  'fingerprint',
                  'secrets',
                  'timestamp'
                  )

class BlacklistSerializer(serializers.ModelSerializer):
    class Meta:
        model = Blacklist
        fields = ('id',
                  'ip',)
        
class TokenSerializer(serializers.ModelSerializer):
    callback = CallbackSerializer(read_only=True)
    token = serializers.CharField(required=False)
    expire_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S", required=False)
    
    class Meta:
        model = Token
        fields = ('token',
                  'callback',
                  'expire_time')
        
class ClientSerializer(serializers.ModelSerializer):
    apikey = serializers.UUIDField(read_only=True)
    update_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S", required=False)
    created_time = serializers.DateTimeField(format="%d-%m-%Y %H:%M:%S", required=False)
    agent = serializers.CharField(read_only=True, required=False)
    source = serializers.CharField(read_only=True, required=False)
    
    class Meta:
        model = Client
        fields = ('id',
                  'apikey',
                  'username',
                  'email',
                  'agent',
                  'update_time',
                  'created_time',
                  'source'
                  )
    