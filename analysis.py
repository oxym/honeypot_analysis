import re
import json
from functools import reduce
from operator import itemgetter
from ip2loc import ip2loc, ip2loc_bulk
from funcs import count_occurence, folding, get_events_before_timestamp, get_first_timestamp, get_unique_values

LOG_FILE_PATH = 'honey.log'

with open(LOG_FILE_PATH, 'r') as f:
    data = f.read()

data = data.splitlines()
data = list(map(lambda x: json.loads(x), data))

################################ Try ################################
# events = reduce(count_occurence('eventid'), data, {})
# events = sorted(events.items(), key=itemgetter(1), reverse=True)
# print(events)
# print('Number of entries: ', len(data))
# print('First entry: ', '\n', data[0])
# print(get_unique_values('eventid', data))
# some_events = list(filter(lambda x: x.get('eventid') == 'cowrie.direct-tcpip.request' , data))
# [print(x) for x in some_events[:1]]
####################################################################

################################ Q1 ################################
failed_logins = list(filter(lambda x: x.get('eventid') == 'cowrie.login.failed', data))
print('1. the number of failed login attemps: ', len(failed_logins))
####################################################################

################################ Q2 ################################
failed_common_usernames = reduce(count_occurence('username'), failed_logins, {})
failed_common_usernames = sorted(failed_common_usernames.items(), key=itemgetter(1), reverse=True)
print('2. the most common failed username: ', failed_common_usernames[0][0])
####################################################################

################################ Q3 ################################
success_logins = list(filter(lambda x: x.get('eventid') == 'cowrie.login.success', data))
print('3. the number of successful login: ', len(success_logins))
####################################################################

################################ Q4 ################################
success_common_usernames = reduce(count_occurence('username'), success_logins, {})
success_common_usernames = sorted(success_common_usernames.items(), key=itemgetter(1), reverse=True)
print('4. the most common successful username: ', success_common_usernames[0][0])
####################################################################

################################ Q5 ################################
failed_ips = reduce(count_occurence('src_ip'), failed_logins, {})
failed_ips = sorted(failed_ips.items(), key=itemgetter(1), reverse=True)
print('5. IP with the most unsuccessful logins: ', failed_ips[0][0])
loc = ip2loc(failed_ips[0][0])
print(f'\tip: {loc.get("ip")}\n\tlocation: {loc.get("region_name")}, {loc.get("country_name")}')
####################################################################

################################ Q6 ################################
login_attempts = success_logins + failed_logins
passwords = reduce(count_occurence('password'), login_attempts, {})
passwords = sorted(passwords.items(), key=itemgetter(1), reverse=True)
print('6. top 10 passwords:\n', [x[0] for x in passwords[:10]])
####################################################################

################################ Q7 ################################
success_root_logins = list(filter(lambda x: x.get('username') == 'root', success_logins))
success_root_logins_by_ip = reduce(folding('src_ip'), success_root_logins, {})
failed_logins_by_ip = reduce(folding('src_ip'), failed_logins, {})
first_try_success_root_login_ips = []
first_try_ever_success_root_login_ips = []

for k, v in success_root_logins_by_ip.items():
    # get the failed logins with the same ip
    same_ip_failed_logins = failed_logins_by_ip.get(k) 

    # no failed logins
    if same_ip_failed_logins is None:
        first_try_success_root_login_ips.append(k)
        first_try_ever_success_root_login_ips.append(k)
        continue

    # get the timestamp of the first success root login
    first_success_login_timestamp = get_first_timestamp(v)

    # get the timestamp of the firt failed login ever
    first_failed_login_timestamp = get_first_timestamp(same_ip_failed_logins)

    if first_success_login_timestamp < first_failed_login_timestamp:
        first_try_success_root_login_ips.append(k)
        first_try_ever_success_root_login_ips.append(k)
        continue

    # get the failed root logins with the same ip
    same_ip_failed_root_logins = list(filter(lambda x: x.get('username') == 'root', same_ip_failed_logins))

    # no failed root login
    if same_ip_failed_root_logins == []:
        first_try_success_root_login_ips.append(k)
        continue

    # get the timestamp of the first failed root login
    first_failed_root_login_timestamp = get_first_timestamp(same_ip_failed_root_logins)

    if first_success_login_timestamp < first_failed_root_login_timestamp:
        first_try_success_root_login_ips.append(k)

print('7. number of unique ips that successfully login as root on first try: ')
print('\t', len(first_try_success_root_login_ips), '(no failed root logins before the first try)')
print('\t', len(first_try_ever_success_root_login_ips), '(no failed logins before the first try)')
####################################################################

################################ Q8 ################################
# get the map of successful root logins by ips
success_root_logins = list(filter(lambda x: x.get('username') == 'root', success_logins))
success_root_logins_by_ip = reduce(folding('src_ip'), success_root_logins, {})
# get the map of failed root logins by ips
failed_root_logins = list(filter(lambda x: x.get('username') == 'root', failed_logins))
failed_root_logins_by_ip = reduce(folding('src_ip'), failed_root_logins, {})
# get the set of ips that failed root login
s1 = get_unique_values('src_ip', failed_root_logins)
# get the set of ips that succeeded root login
s2 = get_unique_values('src_ip', success_root_logins)
# get the intersection of the two sets above
s3 = s1.intersection(s2)
num_of_failed_logins_before_success = sorted(
    map(
        lambda ip: len(
            get_events_before_timestamp(
                failed_root_logins_by_ip.get(ip), 
                get_first_timestamp(
                    success_root_logins_by_ip.get(ip)
                )
            )
        ), s3
    ), reverse=True
)
# print('8. maximum number of failed root logins before the first successful root login:', num_of_failed_logins_before_success[0])
####################################################################

################################ Q9 ################################
command_events = list(filter(lambda x: x.get('eventid') == 'cowrie.command.failed' or x.get('eventid') == 'cowrie.command.input' , data))
command_event_count = reduce(count_occurence('input'), command_events, {})
command_event_count = sorted(command_event_count.items(), key=itemgetter(1), reverse=True)
print('9. five most common commands:')
[print('\t', x[0]) for x in command_event_count[:5]]
####################################################################

################################ Q10 ###############################
regex = r'\.ssh'
match_list = []
for event in command_events:
    match = re.search(regex, event.get('input'))
    if match:
        match_list.append(event)
print('10. line number for a command event that adds a new SSH key: ', 1 + data.index(match_list[0]))
####################################################################