import re
import json
from functools import reduce
from operator import itemgetter
from ip2loc import ip2loc, ip2loc_bulk
from funcs import count_occurence, folding, get_events_before_timestamp, get_timestamp, get_first_timestamp, get_unique_values

LOG_FILE_PATH = 'honey.log'
LOG_FORMAT = '{:27}\t{:33}\t{}'

# configurations
TARGET_IP = '139.219.8.223'
NUM_OF_TO_DISPLAY = 4

with open(LOG_FILE_PATH, 'r') as f:
    data = f.read()

data = data.splitlines()
data = list(map(lambda x: json.loads(x), data))

################################ Try ################################
# success_logins = list(filter(lambda x: x.get('eventid') == 'cowrie.login.success', data))
# success_login_ips = reduce(count_occurence('src_ip'), success_logins, {})
# success_login_ips = sorted(success_login_ips.items(), key=itemgetter(1), reverse=True)
####################################################################

target_ip = TARGET_IP
print('IP to be analyzed: ', target_ip)

# get events with the target ip
target_ip_events = list(filter(lambda x: x.get('src_ip') == target_ip, data))
if target_ip_events == []:
    exit('no record found')

# count number of events per session and sort them in descending order
target_ip_session_count = reduce(count_occurence('session'), target_ip_events, {})
target_ip_session_count = sorted(target_ip_session_count.items(), key=itemgetter(1), reverse=True)
num_of_sessions = len(target_ip_session_count)
print('number of sessions made:', num_of_sessions)
most_interaction_sessions = [x[0] for x in target_ip_session_count[:min(NUM_OF_TO_DISPLAY, num_of_sessions)]]

# get all connect events
target_ip_connect_events = list(filter(lambda x: x.get('eventid') == 'cowrie.session.connect', target_ip_events))

# count sessions by weekday
target_ip_connect_timestamps = [{'weekday':get_timestamp(x).strftime('%a')} for x in target_ip_connect_events]
target_ip_connect_weekday_count = reduce(count_occurence('weekday'), target_ip_connect_timestamps, {})
target_ip_connect_weekday_count = sorted(target_ip_connect_weekday_count.items(), key=itemgetter(1), reverse=True)
print('number of sessions by weekday:')
[print(f'{x[0]} {x[1]}') for x in target_ip_connect_weekday_count]

# group events by session ID
target_ip_events_by_session = reduce(folding('session'), target_ip_events, {})

print('\nSESSIONS WITH THE MOST INTERACTION')
for session in most_interaction_sessions:
    print( '-'*100)
    print('session ID: ', session)

    # get events with the session ID and sort in chronological order
    session_events = target_ip_events_by_session.get(session)
    session_events = sorted(session_events, key=lambda x: get_timestamp(x))
    print('line number in the log that the session starts: ', 1 + data.index(session_events[0]))

    # get the login info
    login = list(filter(lambda x: x.get('eventid') == 'cowrie.login.success', session_events))
    print('login username: ', login[0].get('username'))
    print('login password: ', login[0].get('password'))

    print('\nDETAILS\n', '-'*100)
    
    print(LOG_FORMAT.format('Time', 'Event ID', 'Command'))
    [print(LOG_FORMAT.format(e.get('timestamp'), e.get('eventid'),e.get('input', ''))) for e in session_events]