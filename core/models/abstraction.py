from django.contrib.auth.models import AbstractUser
from django.db import models 


class Users(AbstractUser):
    email_is_verified: models.BooleanField = models.BooleanField(default=False)
    country: models.CharField = models.CharField(max_length=50)
    address: models.CharField = models.CharField(max_length=255)
    city: models.CharField = models.CharField(max_length=255)
    state: models.CharField = models.CharField(max_length=255, null=True, blank=True)
    zipcode: models.CharField = models.CharField(max_length=10)
    phone_number: models.CharField = models.CharField(max_length=20)
    contact_name: models.CharField = models.CharField(max_length=255)
    contact_country: models.CharField = models.CharField(max_length=50)
    contact_address: models.CharField = models.CharField(max_length=255)
    contact_city: models.CharField = models.CharField(max_length=255)
    contact_state: models.CharField = models.CharField(
        max_length=255, null=True, blank=True
    )
    contact_zipcode: models.CharField = models.CharField(max_length=10)
    contact_phone_number: models.CharField = models.CharField(max_length=20)
    
    REQUIRED_FIELDS = [
        'phone_number'
    ]
    
    
class TempCode(models.Model):
    TYPES = [
        ("signin", "signin"),
        ("signup", "signup"),
        ("reset", "reset"),
        ("invite", "invite"),
        ("resend_confirmation", "resend_confirmation"),    
    ]  
    
    code: models.CharField = models.CharField(max_length=255)
    type: models.CharField = models.CharField(max_length=50, choices=TYPES)
    created: models.DateField = models.DateField(auto_now_add=True)
    expires: models.DateField = models.DateField()
    is_used: models.BooleanField = models.BooleanField(default=False)
    user: models.ForeignKey = models.ForeignKey(Users, models.CASCADE) 
    
    class Meta:
        abstract = True 