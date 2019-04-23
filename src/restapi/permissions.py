from rest_framework.permissions import DjangoModelPermissions, BasePermission
from catcher.models import Client
from catcher.settings import USERNAME

class ClientUserPermissions(DjangoModelPermissions):
    def __init__(self):
        self.perms_map['GET'] = ['%(app_label)s.view_%(model_name)s']
        
                