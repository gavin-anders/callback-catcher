from django.contrib import admin
from .models import Callback
from .models import Port
from .models import Handler
from .models import Fingerprint
from .models import Secret
from .models import Blacklist
from .models import Token
from .models import Client

admin.site.register(Callback)
admin.site.register(Port)
admin.site.register(Handler)
admin.site.register(Fingerprint)
admin.site.register(Secret)
admin.site.register(Blacklist)
admin.site.register(Token)
admin.site.register(Client)