from django.core.management.base import BaseCommand
from catcher.models import Client

import os
import sys


class Command(BaseCommand):
    help = 'Creates or changes the password for a user'
    
    def add_arguments(self, parser):
        parser.add_argument('--username', type=str, default="admin", help='Username')
        parser.add_argument('--password', type=str, default="admin", help='Password')

    def handle(self, *args, **kwargs):
        username = kwargs['username']
        password = kwargs['password']

        if Client.objects.filter(username=username).exists():
            print("[+] Changing password for {}".format(username))
            user = Client.objects.get(username=username)
            user.set_password(password)
            user.save()
        else:
            print("[+] Creating new account for {}".format(username))
            superuser = Client.objects.create_superuser(
                username=username,
                email="{}@catcher.com".format(username),
                password=password,
                is_staff=True,
                is_superuser=True
            )



        