# from ast import Mod
# from dataclasses import field
from dataclasses import field
from typing import Union
# from typing_extensions import Required

from django.contrib.auth import get_user_model
from rest_framework.serializers import CharField, IntegerField, ListSerializer
from rest_framework.serializers import ModelSerializer as DrfModelSerializer
from rest_framework.utils.serializer_helpers import ReturnList
from rest_framework_simplejwt.tokens import RefreshToken

User = get_user_model()


class MyListSerializer(ListSerializer):
    @property
    def data(self):
        ret = super().data
        return ReturnList(ret, serializer=self)
    
    
    
class ModelSerializer(DrfModelSerializer):
        class Meta:
            list_serializer_class = MyListSerializer


class PublicUserSerializer(ModelSerializer):
    id = IntegerField()
    username = CharField(required=False)            
    
    class Meta:
        model = User
        fields = ("id", "username", "first_name", "last_name", "is_active")        

class UserSerializer(ModelSerializer):
    id = IntegerField()
    
    class Meta:
        model = User
        fields = (
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "is_active",
            "email_is_verified"
        )
        
    def get_tokens(self, instance: User) -> Union[dict, None]:
        refresh = RefreshToken.for_user(instance)
        
        # print('refresh: ' + str(refresh))
        # print('access_token: ' + str(refresh.access_token))
        
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
        
class ProfileSerializer(ModelSerializer):
    id = IntegerField()
    
    class Meta:
        model = User 
        fields = (
            "id",
            "username", 
            "first_name", 
            "last_name", 
            "email",
            "country",
            "address",
            "city",
            "state",
            "zipcode",
            "phone_number",
            "contact_name",
            "contact_country",
            "contact_address",
            "contact_city",
            "contact_state",
            "contact_zipcode",
            "contact_phone_number",
            
        )   
        
        