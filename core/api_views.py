from asyncio import exceptions
from email import message
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
    ResendCodeInputSerializer,
    SigninInputSerializer,
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
        
        
        
    @swagger_auto_schema(
        operation_summary="Resend",
        operation_description="Resend a code",
        responses={
            200: EmptySerializer(),
            400: BadRequestResponseSerializer(),
            404: NotFoundResponseSerializer(),
        },
        request_body=ResendOTPInputSerializer(),
    )
    
    @action(methods=["POST"], detail=False, url_path="resend/otp")
    
    def resend_otp(self, request, *args, **kwargs):
        try:
            rcv_ser = ResendOTPInputSerializer(data=self.request.data)
            if rcv_ser.is_valid():
                
                user = User.objects.filter(
                    email=rcv_ser.validated_data["email"],
                    is_active=False
                ).first()
                
                if user:
                    tmp_codes = TempCode.objects.filter(
                        user__email=rcv_ser.validated_data["email"], 
                        is_used=False,
                        expires__gte=timezone.now(),
                    ).select_related()
                    
                    tmp_codes.update(is_used=True)
                    
                    try:
                        tmp_codes.save()
                    except:
                        pass
                    
                    code = "54321"
                    TempCode.objects.create(code=code, user=user, type="resend_otp")
                    
                    message = {
                        "email": user.email,
                        "username": user.username,
                    }
                    
                    # TODO Create Apache Kafka Notification
                    
                    return GoodResponse({"Confirmation email sent"})
                    
        
                else:
                    return NotFoundResponse(
                        "User is active or User not found",
                        "user_is_active",
                        request=self.request,
                    )   
                
            else:
                return BadRequestResponse(
                    "Invalid data sent",
                    "invalid_data",
                    data=rcv_ser.errors,
                    request=self.request,
                )
        except Exception as e:
            return BadRequestResponse(str(e), "unknown", request=self.request) 
        
        
    @swagger_auto_schema(
        operation_summary="Resend Email",
        operation_description="Resend Confirmation Email",
        responses={
            200: EmptySerializer(),
            400: BadRequestResponseSerializer(),
            404: NotFoundResponseSerializer(),
        },
        request_body=ResendCodeInputSerializer(),
    )     
    @action(methods=["POST"], detail=False)
    
    def resend(self, request, *args, **kwargs):
        try:
            rcv_ser = ResendCodeInputSerializer(data=self.request.data)
            if rcv_ser.is_valid():
                user = self.request.user
                if user.email_is_verified:
                    return BadRequestResponse(
                        "User is already activated",
                        "user_is_active",
                        data=rcv_ser.errors,
                        request=self.request,
                    )
                tmp_codes = TempCode.objects.filter(
                    user__email=rcv_ser.validated_data["email"],
                    is_used = False,
                    expires__gte = timezone.now(),
                ).select_related()
                    
                code = "54672" 
                fe_url = settings.FRONTEND_URL
                TempCode.objects.filter(
                    code=code, user=user, type="resend_confirmation"
                )
                
                confirm_url = (
                    fe_url
                    + f"/confirm?code={base.url_safe_encode(code)}&firstname={base.url_safe_encode(user.first_name)}&lastname={base.url_safe_encode(user.last_name)}&email={base.url_safe_encode(user.email)}"
                )
                print(confirm_url)
                    
                message = {
                    "subject": _("Confirm Your Email"),
                    "email": self.request.user.email,
                    "confirm_url": confirm_url,
                    "username": self.request.user.username
                }
                    
                # TODO Create Apache Kafka Notification
                
                tmp_codes.update(is_used=True)
                    
                try:
                    tmp_codes.save()
                except:
                    pass
                    
                return GoodResponse({
                    "Confirmation email sent",
                        
                })                        
            
            else:
                return BadRequestResponse(
                    "Invalid data sent",
                    "invalid_data",
                    data=rcv_ser.errors,
                    request=self.request,
                )
            
        except Exception as e:
            return BadRequestResponse(str(e), "Unknown", request=self.request) 
        
    @swagger_auto_schema(
        operation_summary="Signin",
        operation_description="Sign in",
        responses={
            200: EmptySerializer(),
            400: BadRequestResponseSerializer(),
            404: NotFoundResponseSerializer(),
        },
        request_body=SigninInputSerializer(),
    )
    
    @action(methods=["POST"], detail=False)
    
    def signin(self, request, *args, Kwargs):
        try:
            rcv_ser = SigninInputSerializer
        except Exception as e:
            return BadRequestResponse(str(e), "Unknown", request=self.request)
            
               