import string
import sys
import os
import urllib
import cgi2

class MiniFieldStorage:
    def __init__(self, name, value):
        self.name = name
        self.value = value


class FieldStorage:
    def __init__(self, fp=None, environ=os.environ):
        method = string.upper(environ['REQUEST_METHOD'])
        self.fp = sys.stdin
        self.list = None
        if method == 'POST':
            self.read_urlencoded()

    def __getitem__(self, key):
        found = []
        for item in self.list:
            if item.name == key: found.append(item)
        if len(found) == 1:
            return found[0]
        else:
            return found

    def read_urlencoded(self):
        qs = self.fp.read()
        self.list = list = []
        for key, value in cgi2.parse_qsl(qs):
            list.append(MiniFieldStorage(key, value))





