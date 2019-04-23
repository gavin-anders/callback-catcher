from catcher.models import Client
from rest_framework import authentication, exceptions

class ClientHeaderAuthentication(authentication.BaseAuthentication):
    def authenticate(self, request):
        clientapikey = request.META.get('HTTP_CATCHERCLIENT')
        if not clientapikey:
            return None

        try:
            client = Client.objects.get(apikey=clientapikey)
        except Client.DoesNotExist:
            raise exceptions.AuthenticationFailed('Invalid client API key')
        except:
            raise exceptions.ValidationError('API key error')

        return (client, None)