from datetime import datetime
from netaddr import IPNetwork

def strftime(string):
    ''' This returns the current datetime in UTC, formatted using the string
    argument. '''
    time = datetime.utcnow()
    return time.strftime(string)

def lchop(a, max_len, dots='...'):
    ''' Trim the left side of a string until it fits a given length. '''
    if (len(a) > max_len):
        over_len = len(a) - max_len - len(dots)
        return dots + a[over_len:]
    return a

def ip_sort(a, attribute):
    ''' Take list of IPs and sort them '''
    return sorted(a, key=lambda x: int(IPNetwork(x[attribute]).ip))

class FilterModule(object):
    ''' Text manipulation filters '''

    def filters(self):
        return {
            'lchop' : lchop,
            'strftime': strftime,
            'ip_sort': ip_sort,
        }
