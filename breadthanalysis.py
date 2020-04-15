import re
import json
from functools import reduce
from operator import itemgetter
from ip2loc import ip2loc, ip2loc_bulk
from funcs import count_occurence, folding, get_events_before_timestamp, get_timestamp, get_first_timestamp, get_unique_values

LOG_FILE_PATH = 'honey.log'
COUNTRY_STAT_HEADER_FORMAT = '{:<25s}\t{:<10s}\t{:<12s}'
COUNTRY_STAT_FORMAT = '{:<25s}\t{:<10d}\t{:<12.2f}'

REGION_STAT_HEADER_FORMAT = '{:<25s}\t{:<10s}\t{:<12s}'
REGION_STAT_FORMAT = '{:<25s}\t{:<10d}\t{:<12.2f}'

TIME_STAT_HEADER_FORMAT = '{:<25s}\t{:<10s}\t{:<12s}'
TIME_STAT_FORMAT = '{:<25s}\t{:<10d}\t{:<12.2f}'

# configurations
NUM_OF_COUNTRY_TO_DISPLAY = 3
NUM_OF_REGION_TO_DISPLAY = 5
NUM_OF_HOUR_TO_DISPLAY = 8

with open(LOG_FILE_PATH, 'r') as f:
    data = f.read()

data = data.splitlines()
data = list(map(lambda x: json.loads(x), data))

################################ Try ################################
connect_events = list(filter(lambda x: x.get('eventid') == 'cowrie.session.connect', data))
unique_ips = list(get_unique_values('src_ip', connect_events))
locations_by_ip = ip2loc_bulk(unique_ips)
total_num_of_attcks = len(connect_events)
print('TOTAL ATTACKS: ', total_num_of_attcks)
print('\n')

def update(d: dict, u: dict) -> dict:
    d.update(u)
    return d

connect_events = list(
    map(lambda x: 
        update(
            x,
            {
                'region': locations_by_ip.get(x.get('src_ip')).get('region_name'),
                'country': locations_by_ip.get(x.get('src_ip')).get('country_name')
            }
        ), 
        connect_events
    )
)

# aggregate attacks by country
connect_events_count_by_country = reduce(count_occurence('country'), connect_events, {})
connect_events_count_by_country = sorted(connect_events_count_by_country.items(), key=itemgetter(1), reverse=True)
connect_events_by_country = reduce(folding('country'), connect_events, {})

# overall info
num_of_countries = len(connect_events_count_by_country)
print(COUNTRY_STAT_HEADER_FORMAT.format('COUNTRY', 'ATTACKS', 'PERCENTAGE %'))
for country, num_of_attack in connect_events_count_by_country[:min(NUM_OF_COUNTRY_TO_DISPLAY, num_of_countries)]:
    print(COUNTRY_STAT_FORMAT.format(country, num_of_attack, 100 * num_of_attack / total_num_of_attcks))

# detailed breakdown by country
for country, num_of_attack in connect_events_count_by_country[:min(NUM_OF_COUNTRY_TO_DISPLAY, num_of_countries)]:
    same_country_connect_events = connect_events_by_country.get(country)
    connect_events_count_by_region = reduce(count_occurence('region'), same_country_connect_events, {})
    connect_events_count_by_region = sorted(connect_events_count_by_region.items(), key=itemgetter(1), reverse=True)
    connect_events_by_region = reduce(folding('region'), same_country_connect_events, {})
    
    print('\n')
    print(str.upper(country))
    print('-'*100)
    print(REGION_STAT_HEADER_FORMAT.format('REGION', 'ATTACKS', 'PERCENTAGE %'))
    num_of_region = len(connect_events_count_by_region)
    [print(REGION_STAT_FORMAT.format(r, n, 100 * n / num_of_attack)) for r, n in connect_events_count_by_region[:min(NUM_OF_REGION_TO_DISPLAY, num_of_region)]]

    target_country_connect_timestamps = [{'hour':get_timestamp(x).strftime('%H')} for x in same_country_connect_events]
    target_country_connect_hour_count = reduce(count_occurence('hour'), target_country_connect_timestamps, {})
    target_country_connect_hour_count = sorted(target_country_connect_hour_count.items(), key=itemgetter(1), reverse=True)

    num_of_hours = len(target_country_connect_hour_count)
    print('')
    print(TIME_STAT_HEADER_FORMAT.format('HOUR', 'ATTACKS', 'PERCENTAGE %'))
    [print(TIME_STAT_FORMAT.format(t, n, 100 * n / num_of_attack)) for t, n in target_country_connect_hour_count[:min(NUM_OF_HOUR_TO_DISPLAY, num_of_hours)]]

    

####################################################################
# source locations
# attack times

# number of attacks by location