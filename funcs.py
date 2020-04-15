import re
import json
from functools import reduce
from typing import Callable, Dict, AnyStr, List, Set
from operator import itemgetter
from ip2loc import ip2loc, ip2loc_bulk
from datetime import datetime


def count_occurence_helper(field: AnyStr, d: Dict[AnyStr, int], entry: Dict[AnyStr, AnyStr]) -> Dict[AnyStr, int]:
    d[entry[field]] = d.get(entry[field], 0) + 1
    return d


def count_occurence(field: AnyStr) -> Callable[[Dict[AnyStr, int], Dict[AnyStr, AnyStr]], Dict[AnyStr, int]]:
    return lambda d, entry: count_occurence_helper(field, d, entry)


def folding_helper(field: AnyStr, d: Dict[AnyStr, List[Dict[AnyStr, AnyStr]]], entry: Dict[AnyStr, AnyStr]) -> Dict[AnyStr, List[Dict[AnyStr, AnyStr]]]:
    d[entry[field]] = d.get(entry[field], []) + [entry]
    return d


def folding(field: str) -> Callable[[Dict[AnyStr, List[Dict[AnyStr, AnyStr]]], Dict[AnyStr, AnyStr]], Dict[AnyStr, List[Dict[AnyStr, AnyStr]]]]:
    return lambda d, entry: folding_helper(field, d, entry)


def get_unique_values(field: AnyStr, events: List[Dict[AnyStr, AnyStr]]) -> Set[AnyStr]:
    unique_values = set()
    for e in events:
        if (e.get(field)):
            unique_values.add(e.get(field))    
    return unique_values


def get_timestamp(event: Dict[AnyStr, AnyStr]) -> datetime:
    return datetime.strptime(event.get('timestamp'), TIMESTAMP_FORMAT)


def get_first_timestamp(events: List[Dict[AnyStr, AnyStr]]) -> datetime:
    event_timestamps = [datetime.strptime(x.get('timestamp'), TIMESTAMP_FORMAT) for x in events]
    event_timestamps = sorted(event_timestamps)
    first_timestamp = event_timestamps[0]
    return first_timestamp


def get_events_before_timestamp(events: List[Dict[AnyStr, AnyStr]], timestamp: datetime) -> List[Dict[AnyStr, AnyStr]]:
    return list(filter(lambda x: datetime.strptime(x.get('timestamp'), TIMESTAMP_FORMAT) < timestamp, events))


TIMESTAMP_FORMAT = '%Y-%m-%dT%H:%M:%S.%fZ'