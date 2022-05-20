from django.contrib.auth.models import User
from rest_framework import status, viewsets
from rest_framework.decorators import action

from .input_serializer import (
    SignupInputSerializer
)

class AuthViewset(viewsets.ModelViewSet):
    pass