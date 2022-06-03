import enum

from  .base_producer import BaseProducer

class ChannelType(enum.Enum):
    sms = "sms"
    mail = "email"
    push = "push"
    default = "mail"
    
    
    
class NotificationType(enum.Enum):
    signup = "signup"
    reset_init = "reset_init"
    reset = "reset"
    invite = "invite"
    confirm = "confirm"
    change_password = "change_password"
    
    
class NotificationProducer(BaseProducer):
    def __init__(
        self, 
        req_id: str,
        stream_id: str,
        channel: list,
        notification_type: str,
        message
        ):
        
        super().__init__(req_id, stream_id, action=self.ActionType.notification.value)
        
        self.channel = channel
        self.notification_type = notification_type
        self.message = message
    def  extend_event(self) -> dict:
        extended_event = self.event()
        extended_event["message"] = self.message
        extended_event["notification_type"] = self.notification_type
        extended_event["source"] = "authsystem"
        
        return extended_event
    
    def send_notification_event(self):
        event = self.extend_event()
        for c in self.channel:
            event["channel"] = c
            self.send_event(event)      
