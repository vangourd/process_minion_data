import logging
import json
import datetime
import salt.modules.smtp
import os
from pathlib import Path
from pygelf import GelfTcpHandler
from events import EventReference

logger = logging.getLogger(__name__)
evtref = EventReference()
scriptfiles_dir = Path("/srv/salt/_runners/")

def within_limit(evt_name):
    with open(scriptfiles_dir / 'last_seen.json','r+') as file:
        data = file.read()
        if len(data):
            last_seen = json.loads(data)

    if evt_name not in last_seen:
        logger.debug(f"Received {evt_name} has no prior occurence.")
        return False

    tolerance = evtref[evt_name]
    if tolerance:
        occurence = datetime.datetime.fromtimestamp(last_seen[evt_name])
        now = datetime.datetime.now()
        logger.debug(f"Received Now {now}, Occurence {occurence}")
        if (now - occurence) > tolerance:
            logger.debug(f"False: Received {evt_name} is outside the limit period. Tolerance: {tolerance}")
            return False
        else:
            logger.debug(f"True: Received {evt_name} is inside the limit period. Tolerance: {tolerance}")
            return True
    else:
        logger.debug(f"True: Tolerance for {evt_name} not found in events.py")
        return True

def record_event(evt_name):
    timestamp = datetime.datetime.now().timestamp()
    with open(scriptfiles_dir / './last_seen.json','w+') as file:
        data = file.read()
        if len(data):
            last_seen = json.loads(data)
            last_seen[evt_name] = timestamp   
            file.write(json.dumps(last_seen))
        else:
            file.write(json.dumps({evt_name: timestamp}) )

def auth_event(fromaddr, toaddrs, subject, data_str, smtp_server, use_ssl):
    events = {
        "pend": "New minion pending verification",
        "accept": "Minion removed from system",
        "reject": "Minion key rejected by administrator",
        "delete": "Minion key deleted by administrator"
    }
    if within_limit("auth_event:" + data_str.get('act')):
        return False
    else:
        record_event("auth_event:" + data_str.get('act'))
        message = \
        """Salt has detected the following event:
        Event:{0}
        Minion:{1}
        Result:{2}
        """.format(events[data_str.get('act')],data_str['id'],data_str['result'] )
        salt.modules.smtp.send_msg(toaddrs,message, subject="New Salt Event",sender=fromaddr,server=smtp_server, use_ssl=use_ssl)


'''
def email_errors(fromaddr, toaddrs, subject, data_str, smtp_server,use_ssl):
    log.debug(data_str.keys())
   
    error = False
    changes = False

    if isinstance(data.get('return'),dict):
        for state, result in data['return'].iteritems():
            if not result['result']:
                error = True
                break
            if result['changes']:
                error = True
                break
    else:
        if not data.get('success'):
            error = True

    if error or changes:
        body = subprocess.check_output(["salt-run", "jobs.lookup_jid", data.get['jid']])
        salt.modules.smtp.send_msg(toaddrs, body, subject=subject, sender=fromaddr, server=smtp_server, use_ssl=use_ssl)
       
    return True
    '''
