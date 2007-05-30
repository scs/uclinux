from ipodlib import *

ipodPaths = IPod.Discover()
for ipodPath in ipodPaths:
	ipod = IPod(ipodPath)
	for presetIndex in xrange(ipod.EQPresetCount()):
		preset = ipod.EQPresetByIndex(presetIndex)
		print "Index %d '%s'" % (presetIndex,preset.GetText(IPOD_TITLE))
		print "  Preamp %d" % preset.GetAttribute(IPOD_EQ_PRESET_PREAMP)
		for i in xrange(10):
			print "  iTunes Preset %d: %d" % (i,preset.GetAttribute(IPOD_EQ_PRESET_BAND_A_BASE+i))
		for i in xrange(5):
			print "  iPod Preset %d: %d" % (i,preset.GetAttribute(IPOD_EQ_PRESET_BAND_B_BASE+i))