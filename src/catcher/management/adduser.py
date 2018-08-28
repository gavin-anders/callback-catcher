from django.core.management.base import BaseCommand

class Command(BaseCommand):
    def handle_noargs(self, **options):
        # now do the things that you want with your models here
        print("[+] Add a new user")