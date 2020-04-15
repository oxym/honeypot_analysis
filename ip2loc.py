from typing import List, Dict
import json
import grequests

GEO_API_KEY = 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
GEO_API_END_POINT = 'http://api.ipstack.com/'
IP2LOC_CACHE = 'ip2loc.json'

def ip2loc(ip: str) -> dict:
    ip2loc_dict = ip2loc_bulk([ip])
    return ip2loc_dict.get(ip)
    

def ip2loc_bulk(ips: List[str]) -> Dict[str, dict]:

    try:
        with open(IP2LOC_CACHE, 'r') as f:
            data = f.read()
            ip2loc_dict = json.loads(data)
    except FileNotFoundError as err:
        print(err)
        ip2loc_dict = {}

    locations = {}
    urls = []
    for ip in ips:
        cached_result = ip2loc_dict.get(ip)
        if cached_result:
            locations[ip] = cached_result
        else:
            urls.append(f'{GEO_API_END_POINT}{ip}?access_key={GEO_API_KEY}&fields=ip,region_name,country_name')

    if urls == []:
        return locations

    print('getting location info...')
    rs = (grequests.get(u) for u in urls)
    for response in grequests.imap(rs):
        if not response.ok:
            data = json.loads(response.content)
            empty_entry = {
                'ip': data.get('ip'),
                'region_name': 'None',
                'country_name': 'None'
            }
            locations[data.get('ip')] = empty_entry
            ip2loc_dict[data.get('ip')] = empty_entry
            continue

        data = json.loads(response.content)
        if not data.get('country_name'):
            data['country_name'] = 'None'
        if not data.get('region_name'):
            data['region_name'] = 'None'
        locations[data.get('ip')] = data
        ip2loc_dict[data.get('ip')] = data

    with open(IP2LOC_CACHE, 'w+') as f:    
        json.dump(ip2loc_dict, f)

    return locations

if __name__ == "__main__":
    locations = ip2loc_bulk(['221.5.135.10', '221.22.135.33'])
    for ip in locations.keys():
        print(f'ip: {locations.get(ip).get("ip")}\tlocation: {locations.get(ip).get("region_name")}, {locations.get(ip).get("country_name")}')