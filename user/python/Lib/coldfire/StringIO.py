import string

class StringIO:
	def __init__(self, buf = ''):
		self.buf = buf
		self.len = len(buf)
		self.buflist = []
		self.pos = 0
		self.closed = 0

	def read(self, n = -1):
		if self.closed:
			raise ValueError, "I/O operation on closed file"
		if self.buflist:
			self.buf = self.buf + string.joinfields(self.buflist, '')
			self.buflist = []
		if n < 0:
			newpos = self.len
		else:
			newpos = min(self.pos+n, self.len)
		r = self.buf[self.pos:newpos]
		self.pos = newpos
		return r
		
