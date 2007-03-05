#
# configure.py
#
# Duane Maxwell
# (c) Copyright Linspire. Inc, 2005
#
# This is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
#
import os
import sipconfig

modulename = "ipodlib"
buildfile = modulename+".sbf"
config = sipconfig.Configuration()
os.system(" ".join([config.sip_bin, '-c', '.', '-b', buildfile, modulename+".sip"]))
makefile = sipconfig.SIPModuleMakefile(config,buildfile,installs=[["ipod.py",config.default_mod_dir]])
makefile.extra_lib_dirs = [".","../src","../src/.libs"]
makefile.extra_libs = ["ipod","expat"]
makefile.extra_include_dirs = [".","../src","../include"]
makefile.generate()
