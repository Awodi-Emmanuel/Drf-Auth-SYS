from django.utils import timezone
from .abstraction import TempCode as AbstractTempCode


class TempCode(AbstractTempCode):
    def save(self, *arg, **kwargs):
        from datetime import timedelta
        
        self.expires = timezone.now + timedelta(minutes=10)
        super.save(*arg, *kwargs)
    
    @classmethod 
    
    def get_string_code(cls, codetype: str):
              if codetype == "signup":
                  return "12345"
              else:
                  return "ab243d-ef1452"