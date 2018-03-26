from rest_framework.permissions import BasePermission, SAFE_METHODS

class IsUser(BasePermission):
    """
    For logged in users only
    """
    def has_permission(self, request, view):
        return request.user.is_staff
    
class IsAnonymous(BasePermission):
    """
    For admin users only
    """
    def has_permission(self, request, view):
        return request.user.is_staff
    
