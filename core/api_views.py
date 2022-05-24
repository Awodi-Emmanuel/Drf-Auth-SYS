from asyncio import exceptions
import logging
import traceback

from requests import request

from core.pagination import MetadataPagination, MetadataPaginatorInspector
from django.utils.decorators import method_decorator
from django.utils import timezone
from django.contrib.auth import get_user_model
from django.contrib.auth.models import AbstractBaseUser
from rest_framework.authtoken.models import Token
from core.custom_classes import YkGenericViewSet
from rest_framework.views import APIView
from django.contrib.auth import login, logout
import logging
from django.utils.translation import gettext as _
from uuid import uuid4
from datetime import timedelta, datetime
from rest_framework.viewsets import ViewSet, ModelViewSet, GenericViewSet
# from rest_framework.mixins import (
#     ListModelMixin,
#     UpdateModelMixin,
#     DestroyModelMixin,
#     CreateModelMixin,
#     RetrieveModelMixin,
# )

from core.models import TempCode

from rest_framework.decorators import action
from django.db.models import Q
from drf_yasg import openapi  # type: ignore
from drf_yasg.utils import swagger_auto_schema  # type: ignore

from core.responses import (
    GoodResponse,
    BadRequestResponse,
    NotFoundResponse,
    CreatedResponse,
)

from core.responses_serializers import (
    BadRequestResponseSerializer,
    EmptySerializer,
    NotFoundResponseSerializer,
)    
from AuthSystem import settings
from core.custom_classes import YkGenericViewSet
from core.errors import BadRequestError, NotFoundError
from .input_serializer import (
    SignupInputSerializer,
    ConfirmInputSerializer,
    ValidateOTPInputSerializer,
    ResendOTPInputSerializer,
)

from .model_serializer import (
    UserSerializer
)

from utils import base, crypt

logger = logging.getLogger()

User = get_user_model()



class AuthViewset(YkGenericViewSet):
    @swagger_auto_schema(
        operation_summary="Signup",
        operation_description="Signup using your email",
        responses={200: EmptySerializer(), 400: BadRequestResponseSerializer()},
        request_body=SignupInputSerializer(),
    )
    @action(methods=["POST"], detail=False)
    def signup(self, request, *args, **kwargs):
        try:
            rcv_ser = SignupInputSerializer(data=self.request.data)
            if rcv_ser.is_valid():
                user = rcv_ser.create_user()
                if not user.is_active:
                   code = "12345" # TODO: Create and add code generation function
                   code_otp = "546387"
                   fe_url = settings.FRONTEND_URL
                   TempCode.objects.create(code=code, user=user, type="signup")
                   TempCode.objects.create(code=code_otp, user=user, type="signup_otp")
                   confirm_url = (
                       fe_url
                       + f"/confirm?code={crypt.encrypt(code)}&firstname={crypt.encrypt(user.first_name)}&lastname={crypt.encrypt(user.last_name)}&email={crypt.encrypt(user.email)}"
                   )
                   
                   
                   message = {
                       "subject": _("Confirm Your Email"),
                       "email": user.email,
                       "confirm_url": confirm_url,
                       "username": user.username,
                   }
                   # TODO: Create Apache Kafka
                   
                   message = {
                       "subject": _("Confirm Your Email"),
                       "phone": user.phone_number,
                       "code": code_otp,
                       "username": user.username,
                   }
                   # TODO: Create  Apache Kafka
                
                return CreatedResponse({"message": "user created"})
            
            else:
                return BadRequestResponse(
                    "unable to signup", 
                    "signup_error", 
                    data=rcv_ser._errors, 
                    request=self.request
                )
                
               
        except Exception as e:
            logger.error(traceback.print_exc())
            return BadRequestResponse(str(e), code="unknown", request=self.request)
        
    @swagger_auto_schema(
        operation_summary="Confirm",
        operation_description="Confirm your email",
        responses={
            200: EmptySerializer(),
            400:BadRequestResponseSerializer(),
            404: NotFoundResponseSerializer(),
            },
        request_body=ConfirmInputSerializer()
    )    
    @action(methods=["POST"], detail=False)
    
    def confirm(self, request, *args, **kwargs):
        try:
            rcv_ser = ConfirmInputSerializer(data=self.request.data)
            if rcv_ser.is_valid():
                print(crypt.encrypt(rcv_ser.validated_data["code"]))
                tmp_code = (
                    TempCode.objects.filter(
                        code=crypt.encrypt(rcv_ser.validated_data["code"]),
                        user__email=crypt.encrypt(
                            rcv_ser.validated_data["email"]
                        ),
                        is_used = False,
                        expires__gte=timezone.now(),
                    )
                    .select_related()
                    .first()
                )
                if tmp_code:
                    tmp_code.user.email_is_verified = True
                    tmp_code.user.save()
                    tmp_code.is_used = True
                    tmp_code.save()
                    user_ser = UserSerializer(tmp_code.user)
                    
                    message = {
                        "subject": _("Welcome To Testing"),
                        "email": tmp_code.user.email,
                        "username": tmp_code.user.username,
                    }
                    
                    # TODO Apache Kafka
                    
                    return GoodResponse(user_ser.data)
                else:
                    return NotFoundResponse(
                        "TempCode not found or invalid",
                        "TempCode",
                        request=self.request
                    )
            else:
                return BadRequestResponse(
                    "Unable to confirm",
                    "confirm_error",
                    request=self.request,
                )        
        except Exception as e:
            logger.error(traceback.print_exc())
            return BadRequestResponse(str(e), "unknown", request=self.request)      
    
    
    @swagger_auto_schema(
        operation_summary="Validate OTP",
        operation_description="Validate the OTP",
        responses={200: GoodResponse(), 400:BadRequestResponseSerializer()},
        request_body=ValidateOTPInputSerializer(),
    )

    @action(methods=["POST"], detail=False, url_path="validate/otp")
    
    def validate_otp(self, request, *args, **kwargs):
        try:
            rcv_ser = ValidateOTPInputSerializer(data=self.request.data)
            if rcv_ser.is_valid():
                tmp_code = (
                    TempCode.objects.filter(
                        code=base.url_safe_decode(rcv_ser.validated_data["otp"]),
                        email=base.url_safe_decode(rcv_ser.validated_data["email"]),
                    is_used=False,
                    expires__gte=timezone.now(),    
                    )
                    .select_related()
                    .first()
                )
                if tmp_code:
                    tmp_code.user.is_active = True
                    tmp_code.user.save(),
                    tmp_code.user.is_used = True
                    tmp_code.save()
                    user_ser = UserSerializer(tmp_code.user)
                    return GoodResponse(user_ser.data)
                
                else: 
                    return NotFoundResponse(
                    "OTP not found or invalid", "OTP", request=self.request
                )
            else:
                return BadRequestResponse(
                    "Unable to validate OTP",
                    "otp_validation_error",
                    data=rcv_ser.errors,
                    request=self.request,
                )       
            
        except Exception as e:
            return BadRequestResponse(str(e), "unknown", request=self.request)  
        
        
        
   