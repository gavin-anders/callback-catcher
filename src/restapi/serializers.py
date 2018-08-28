from catcher.models import Handler, Callback, Fingerprint, Port, Handler, Secret, Token
from django.contrib.auth.models import User
from rest_framework import serializers
from django.shortcuts import get_object_or_404
import pprint

class SecretSerializer(serializers.ModelSerializer):
    class Meta:
        model = Secret
        fields = (
              'name',
              'value'
            )

class TokenSerializer(serializers.ModelSerializer):
    class Meta:
        model = Token
        fields = ('id',
                  'name',
                  'token'
                  )
        
class FingerprintSerializer(serializers.ModelSerializer):
    class Meta:
        model = Fingerprint
        fields = ('name', 
                  'probe',)

class HandlerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Handler
        fields = ('id',
                  'name',
                  'description', 
                  'filename', 
                  'settings')

class PortSerializer(serializers.ModelSerializer):
    class Meta:
        model = Port
        fields = ('id',
                  'number', 
                  'protocol', 
                  'ssl',  
                  'handler',
                  'pid')
        
class CallbackSerializer(serializers.ModelSerializer):
    secrets = SecretSerializer(many=True, read_only=True)
    tokens = TokenSerializer(many=True, read_only=True)
    fingerprint = serializers.StringRelatedField(many=False)

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
                  'tokens',
                  'secrets',
                  )

        
    