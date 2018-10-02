from catcher.models import Handler, Callback, Fingerprint, Port, Handler, Secret, Blacklist
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
    settings = serializers.CharField(read_only=False)
    
    class Meta:
        model = Handler
        fields = ('id',
                  'name',
                  'description', 
                  'filename', 
                  'settings')

class PortSerializer(serializers.ModelSerializer):
    handler = serializers.SlugRelatedField(many=False, required=False, queryset=Handler.objects.all(), slug_field='filename')

    class Meta:
        model = Port
        fields = ('id',
                  'number', 
                  'protocol', 
                  'ssl',  
                  'handler')
        
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
    