def upper(s):
    return s.upper()

def split(s, sep=None, maxsplit=-1):
    return s.split(sep, maxsplit)
splitfields = split

def join(words, sep = ' '):
    return sep.join(words)
joinfields = join

_int = int

def atoi(s , base=10):
    return _int(s, base)

def replace(s, old, new, maxsplit=-1):
    return s.replace(old, new, maxsplit)
