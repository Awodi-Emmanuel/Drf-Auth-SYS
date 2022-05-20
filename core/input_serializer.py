from rest_framework.serializers import Serializer, ValidationError
from rest_framework.fields import *
from django.contrib.auth import get_user_model
from django.core.validators import validate_email as dj_validate_email
from django.utils.translation import gettext as _
from django.db.models import Q
from django.contrib.auth.models import AbstractBaseUser
from typing import Union
from core.models import TempCode
from django.utils import timezone

from uuid import uuid4
from datetime import timedelta, datetime
from django.utils import timezone
import pytz

User: AbstractBaseUser = get_user_model()

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
        # if u and u.date_joined >= datetime(2022, 1, 1, tzinfo=pytz.UTC):
        if u:
            raise ValidationError("This username is alreday used.")
        return username
    
    def validate_email(self, args):
        email = self.initial_data["email"]
        try:
            dj_validate_email(email)    
            u = User.objects.filter(email=email).first()
            # if u and u.date_joined >= datetime(2022, 1, 1, tzinfo=pytz.UTC):
            if u:
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
                user.date_joined = datetime.utcnow()
                user.save()
            else:
                raise ValidationError("This invite code is invalid")
        return user        