import string
import urllib
def parse_qsl(qs):

    pairs = [s2 for s1 in qs.split('&') for s2 in s1.split(';')]
    r = []
    for name_value in pairs:
        nv = name_value.split('=', 1)
        if len(nv[1]):
            name = urllib.unquote(string.replace(nv[0], '+', ' '))
            value = urllib.unquote(string.replace(nv[1], '+', ' '))
            r.append((name, value))

    return r
