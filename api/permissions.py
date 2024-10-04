from rest_framework.permissions import BasePermission

class IsAdmin(BasePermission):
    """
    Allows access only to admin users.
    """
    def has_object_permission(self, request, view, obj):
        return obj.email == request.user.email

class IsPatient(BasePermission):
    """
    Allows access only to patient users.
    """
    def has_object_permission(self, request, view, obj):
        return obj.email == request.user.email
    
# class IsPatient(BasePermission):
#     """
#     Allows access only to users who are patients.
#     """

#     def has_permission(self, request, view):
#         # Check if the user is authenticated and is marked as a patient
#         return request.user and request.user.is_authenticated  

class IsHospital(BasePermission):
    """
    Allows access only to the hospital owner.
    """
    def has_object_permission(self, request, view, obj):
        return obj.email == request.user.email


# class IsHospital(BasePermission):
#     def has_permission(self, request, view):
#         return request.user and request.user.is_authenticated and hasattr(request.user, 'hospital')
    
#     def has_object_permission(self, request, view, obj):
#         return obj.email == request.user.email
