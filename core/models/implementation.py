from django.utils import timezone
from .abstraction import TempCode as AbstractTempCode


class TempCode(AbstractTempCode):
    def save(self, *arg, **kwargs):
        from datetime import timedelta