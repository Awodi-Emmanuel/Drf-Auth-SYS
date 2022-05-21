from email import message
import logging
import traceback

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
from rest_framework.mixins import (
    ListModelMixin,
    UpdateModelMixin,
    DestroyModelMixin,
    CreateModelMixin,
    RetrieveModelMixin,
)

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
    SignupInputSerializer
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
                   code = "12345"
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
                   # TODO:  Apache Kafka
                   
                   message = {
                       "subject": _("Confirm Your Email"),
                       "phone": user.phone_number,
                       "code": code_otp,
                       "username": user.username,
                   }
                   # TODO:  Apache Kafka
                
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
    
        