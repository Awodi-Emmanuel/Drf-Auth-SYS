from datetime import datetime, timedelta
from typing import Union
from uuid import uuid4
from pkg_resources import require

import pytz
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from django.core.validators import validate_email as dj_validate_email
from django.db.models import Q
from django.utils import timezone
from django.utils.translation import gettext as _
from rest_framework.fields import *
from rest_framework.serializers import Serializer, ValidationError



from core.models import TempCode

User = get_user_model()


class SignupInputSerializer(Serializer):
    username = CharField()
    first_name = CharField()
    last_name = CharField()
    email = EmailField()
    phone = CharField()
    password = CharField()
    invite_code = CharField(required=False)  
    
      
    class Meta:
        ref_name = None
        
    def validate_username(self, *args):
        username = self.initial_data["username"]
        u = User.objects.filter(username=username).first()
        if u:
        #and u.date_joined >= datetime(2020, 1, 1, tzinfo=pytz.UTC):
            
            raise ValidationError("This username is already used.")
        return username
    
    def validate_email(self, args):
        email = self.initial_data["email"]
        try:
            dj_validate_email(email)    
            user = User.objects.filter(email=email).first()
            # if u and u.date_joined >= datetime(2022, 1, 1, tzinfo=pytz.UTC):
            if user:
                raise ValidationError("This email is already used.")
        except ValidationError as e:
            raise e 
           
        return email
    
    
    def create_user(self, *arg):
        username = self.validated_data["username"]
        email = self.validated_data["email"]
        phone = self.validated_data["phone"]
        first_name = self.validated_data["first_name"]
        last_name = self.validated_data["last_name"]
        password = self.validated_data["password"]
        
        user = User.objects.filter(email=email).first()
        
        if not user:
            user = User.objects.create_user(
                username=username,
                email=email,
                phone_number=phone,
                first_name=first_name,
                last_name=last_name,
                password=password,
            )
            user.is_active = False
            user.save()
        else:
            invite_code = self.validated_data.get("invite_code")
            tmp_code = TempCode.objects.filter(
                code=invite_code, user=user, expires__gte=timezone.now(), is_used=False
            ).first()
            if tmp_code:
                user.first_name = first_name
                user.last_name = last_name
                if password:
                    user.set_password(password)
                if username:
                    user.username = username
                user.is_active = True    
                user.date_joined = datetime.utcnow()
                user.save()
                
                tmp_code.is_used = True
                tmp_code.save()
            else:
                raise ValidationError("This invite code is invalid")
        return user  
    
class SigninInputSerializer(Serializer):
    email = EmailField(required=False, allow_null=True)
    username = CharField(required=False, allow_null=True)
    Password = CharField()    
    
    class Meta:
        ref_name = None
        
    def validate_password(self, *args):
        username = self.initial_data.get("username")
        email = self.initial_data.get("email")
        password = self.initial_data.get("password")
        
        if not email and not username:
            raise ValidationError(_("(username or email) fields should be present.")) 
        
        return password  
    
class ChangePasswordSerializer(Serializer):
    old_password = CharField()
    new_password = CharField()
    confirmed_password = CharField()
    
    class Meta:
        ref_name = None
    
class ResetWithPassInputSerializer(Serializer):
    email = EmailField()
    code = CharField()
    password = CharField()
    
    class Meta:
        ref_name = None    
        
class ConfirmInputSerializer(Serializer):
    email = EmailField()
    code = CharField()
    
    class Meta:
        ref_name = None   
        
class ValidateOTPInputSerializer(Serializer):
    email = EmailField(),
    otp = CharField()
    
    class Meta:
        ref_name = None
        
class ResetInputSerializer(Serializer):
    email = EmailField()
    
    class Meta:
        ref_name = None        
                   
class ResendOTPInputSerializer(Serializer):
    email = EmailField()
        
    
    class Meta:
        ref_name = None 
        
class ResendCodeInputSerializer(Serializer):
    email = EmailField()
    
    class Meta:
        ref_name = None 
        
        
                             