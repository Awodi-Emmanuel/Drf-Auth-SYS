from ctypes import Union
from ensurepip import bootstrap
import enum
import json
from multiprocessing.sharedctypes import Value
from webbrowser import BaseBrowser  

from kafka import kafkaProducer 

BOOSTSRAP_SERVERS = ['localhost:9092']

class BaseProducer:
    class ActionType(enum.Enum):
        notification = "notification"
        default = "notification"
        
        
    def __init__(self, req_id: str, stream_id: str, action)  -> None:
        self.req_id = req_id,
        self.stream_id = stream_id,
        self.action = action if action is not None else BaseBrowser.ActionType.default
        
        
    def event(self):
        event = {
            "req_id": self.req_id,
            "stream_id": self.stream_id,
        }   
        
        return event 
    
    def send_event(self, event):
        producer = kafkaProducer(
            value_serializer=lambda v:json.dumps(v).encode("utf-8"),
            bootstrap_servers=BOOSTSRAP_SERVERS,
        )
        
        producer.send(topic=self.action, value=event)