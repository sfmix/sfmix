import sys
import re


def last_octet(a):
	''' This splits off the last octet from an IP address.'''
	return int (re.search(r'.*\.(.*)\/\d', a).group(1))

class FilterModule(object):
    ''' general python jinja2 custom filters '''

    def filters(self):
        return {
            'last_octet'  : last_octet,
        }
