from datetime import timedelta

class EventReference:

    def __init__(self):
        self._events = {
            "auth_event:accept": timedelta(minutes=1), 
            "auth_event:pend": timedelta(minutes=5)
        }

    def __getitem__(self,key):
        return self._events.get(key)
