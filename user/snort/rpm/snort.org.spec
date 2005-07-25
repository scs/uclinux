# $Id$
# Snort.org's SPEC file for Snort

################################################################
# rpmbuild Package Options
# ========================
#
# See README.build_rpms for more details.
#
# 	--with flexresp
# 		Add flexresp capability to whatever package(s) you are
# 		building.
# 
# 	--with mysql
# 		Builds a binary/package with support for MySQL.
# 
# 	--with postgresql
# 		Builds a binary/package with support for PostgreSQL.
# 
# 	--with oracle
# 		Builds a binary/package with support for Oracle.
#
#	--with fedora
#		Builds with Fedora's naming scheme
#
# See pg 399 of _Red_Hat_RPM_Guide_ for rpmbuild --with and --without options.
################################################################

# Other useful bits
%define OracleHome    /opt/oracle/OraHome1
%define SnortRulesDir /etc/snort/rules

# Handle the options noted above.
# Default of no flexresp, but --with flexresp will enable it
%define flexresp 0
%{?_with_flexresp:%define flexresp 1}

# Default of no MySQL, but --with mysql will enable it
%define mysql 0
%{?_with_mysql:%define mysql 1}

# Default of no PostgreSQL, but --with postgresql will enable it
%define postgresql 0
%{?_with_postgresql:%define postgresql 1}

# Default of no Oracle, but --with oracle will enable it
%define oracle 0
%{?_with_oracle:%define oracle 1}

# In case we are building for Fedora
%define vendor Snort.org
%define for_distro RPMs
%define fedora 0
%{?_with_fedora:%define vendor Fedora Linux }
%{?_with_fedora:%define for_distro RPMs for Fedora Linux }

# Look for a directory to see if we're building under cAos 
# Exit status is usually 0 if the dir exists, 1 if not, so
# we reverse that with the '!'
%define caos %([ ! -d /usr/lib/rpm/caos ]; echo $?)

%if %{caos}
  # We are building for cAos (www.caosity.org) and the autobuilder doesn't
  # have command line options so we have to fake the options for whatever
  # packagaes we actually want here, in addition to tweaking the package
  # info.
  %define vendor cAos Linux 
  %define for_distro RPMs for cAos Linux
  %define mysql 1
  %define postgresql 1
%endif


# Be sure to update the release and fedora release numbers!
###########################################################
%define release 1
%{?_with_fedora:%define release 0.fdr.1 }
%if %{caos}
  %define release 1.caos
%endif
###########################################################

Summary: An open source Network Intrusion Detection System (NIDS)
Name: snort
Version: 2.3.3
Release: %{release}
Epoch: 0
License: GPL
Group: Applications/Internet
Source0: http://www.snort.org/dl/%{name}-%{version}.tar.gz
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
Url: http://www.snort.org/
Packager: Official Snort.org %{for_distro}
Vendor: %{vendor}
Distribution: %{vendor}
BuildRequires: pcre-devel, libpcap
Requires: pcre, libpcap

%if %{flexresp}
BuildRequires: libnet
  %define EnableFlexresp --enable-flexresp
%endif


%package mysql
Summary: Snort with MySQL support
Group: Applications/Internet
Requires: %{name} = %{epoch}:%{version}-%{release}
%if %{mysql}
BuildRequires: mysql-devel
%endif

%description mysql
Snort binary compiled with mysql support.


%package postgresql
Summary: Snort with PostgreSQL support
Group: Applications/Internet
Requires: %{name} = %{epoch}:%{version}-%{release}
%if %{postgresql}
BuildRequires: postgresql-devel
%endif

%description postgresql
Snort binary compiled with postgresql support. 


%package oracle
Summary: Snort with Oracle support
Group: Applications/Internet
Requires: %{name} = %{epoch}:%{version}-%{release}

%description oracle
Snort binary compiled with Oracle support. 

EXPERIMENTAL!!  I don't have a way to test this, so let me know if it works!
ORACLE_HOME=%{OracleHome}


%description
Snort is an open source network intrusion detection system, capable of
performing real-time traffic analysis and packet logging on IP networks.
It can perform protocol analysis, content searching/matching and can be
used to detect a variety of attacks and probes, such as buffer overflows,
stealth port scans, CGI attacks, SMB probes, OS fingerprinting attempts,
and much more.

Snort has three primary uses. It can be used as a straight packet sniffer
like tcpdump(1), a packet logger (useful for network traffic debugging,
etc), or as a full blown network intrusion detection system. 

You MUST edit /etc/snort/snort.conf to configure snort before it will work!

There are 3 different packages available. All of them require the base
snort rpm (this one). Additionally, you may need to chose a different
binary to install if you want database support.

If you install a different binary package %{_sbindir}/snort should end up
being a symlink to a binary in one of the following configurations:

	plain		Snort (this package, required)
	mysql		Snort with mysql (optional)
	postgresql	Snort with postgresql (optional)
	oracle		Snort with oracle (optional, not official)

Please see the documentation in %{_docdir}/%{name}-%{version}, especially
README.build_rpms if you would like to build your own custom RPM.


%prep
# Make sure buildroot is not insane
if [ "$RPM_BUILD_ROOT" == "/" ]; then
    echo 'Invalid Build root'
    exit 1
fi


%setup -q -n %{name}-%{version}

# When building from a Snort.org CVS snapshot tarball, you have to run
# autojunk before you can build.
if [ \( ! -s configure \) -a \( -x autojunk.sh \) ]; then
    ./autojunk.sh
fi

# Make sure it worked, or die with a useful error message.
if [ ! -s configure ]; then
    echo "Can't find ./configure.  ./autojunk.sh not present or not executable?"
    exit 2
fi


%build

BuildSnort() {
   mkdir "$1"
   cd "$1"
   ln -s ../configure ./configure

   if [ "$1" = "plain" ] ; then
	./configure $SNORT_BASE_CONFIG \
	--without-mysql \
	--without-postgresql \
	--without-oracle \
	%{?EnableFlexresp} %{?EnableFlexresp2} 
   fi

   if [ "$1" = "mysql" ]; then
	./configure $SNORT_BASE_CONFIG \
	--with-mysql \
	--without-postgresql \
	--without-oracle \
	%{?EnableFlexresp} %{?EnableFlexresp2}
   fi

   if [ "$1" = "postgresql" ]; then
	./configure $SNORT_BASE_CONFIG \
	--without-mysql \
	--with-postgresql \
	--without-oracle \
	%{?EnableFlexresp} %{?EnableFlexresp2}
   fi

   if [ "$1" = "oracle" ]; then
	export ORACLE_HOME=%{OracleHome}
	./configure $SNORT_BASE_CONFIG \
	--without-mysql \
	--without-postgresql \
	--with-oracle=$ORACLE_HOME \
	%{?EnableFlexresp} %{?EnableFlexresp2}
   fi

   make 
   mv src/snort ../snort-"$1"
   cd ..
}


CFLAGS="$RPM_OPT_FLAGS"
export AM_CFLAGS="-g -O2"
SNORT_BASE_CONFIG="--prefix=%{_prefix} \
                   --bindir=%{_sbindir} \
                   --sysconfdir=/etc/snort \
		   --with-libpcap-includes=%{_includedir} \
		   --without-odbc"

# Always build snort-plain
BuildSnort plain

# Mayby build the others
%if %{mysql}
  BuildSnort mysql
%endif

%if %{postgresql}
  BuildSnort postgresql
%endif

%if %{oracle}
  BuildSnort oracle
%endif


%install

# Remove leftover CVS files in the tarball, if any...
find . -type 'd' -name "CVS" -print | xargs %{__rm} -rf

# Fix a double path in the signature dir
#
# (NOTE, this no longer changes the location of doc/signatures
if [ -d doc/signatures/signatures ]; then
	mv doc/signatures/signatures/* doc/signatures
    rmdir doc/signatures/signatures
fi

InstallSnort() {
   if [ "$1" = "mysql" ]; then
	install -p -m 0755 snort-mysql $RPM_BUILD_ROOT%{_sbindir}/snort-mysql
   fi

   if [ "$1" = "postgresql" ]; then
   	install -p -m 0755 snort-postgresql $RPM_BUILD_ROOT%{_sbindir}/snort-postgresql
   fi

   if [ "$1" = "oracle" ]; then
   	install -p -m 0755 snort-oracle $RPM_BUILD_ROOT%{_sbindir}/snort-oracle
   fi

   if [ "$1" = "plain" ]; then
	if [ -d $RPM_BUILD_ROOT ] && [ "$RPM_BUILD_ROOT" != "/" ]; then
	   rm -rf $RPM_BUILD_ROOT
	fi

	mkdir -m 0755 -p $RPM_BUILD_ROOT%{_sbindir}
    	mkdir -m 0755 -p $RPM_BUILD_ROOT%{SnortRulesDir}
	mkdir -m 0755 -p $RPM_BUILD_ROOT/etc/snort
	mkdir -m 0755 -p $RPM_BUILD_ROOT/etc/sysconfig
	mkdir -m 0755 -p $RPM_BUILD_ROOT/etc/logrotate.d
	mkdir -m 0755 -p $RPM_BUILD_ROOT/var/log/snort
	mkdir -m 0755 -p $RPM_BUILD_ROOT/etc/init.d
	mkdir -m 0755 -p $RPM_BUILD_ROOT%{_mandir}/man8
	mkdir -m 0755 -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc
	mkdir -m 0755 -p $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc/signatures

	install -p -m 0755 snort-plain $RPM_BUILD_ROOT%{_sbindir}/snort-plain
	install -p -m 0644 snort.8 $RPM_BUILD_ROOT%{_mandir}/man8
	gzip $RPM_BUILD_ROOT%{_mandir}/man8/snort.8
	install -p -m 0755 rpm/snortd $RPM_BUILD_ROOT/etc/init.d
	install -p -m 0644 rpm/snort.sysconfig $RPM_BUILD_ROOT/etc/sysconfig/%{name}
	install -p -m 0644 rpm/snort.logrotate $RPM_BUILD_ROOT/etc/logrotate.d/snort
	install -p -m 0644 rules/*.rules $RPM_BUILD_ROOT/%{SnortRulesDir}
	install -p -m 0644 etc/reference.config etc/classification.config \
	   etc/unicode.map etc/gen-msg.map etc/sid-msg.map \
	   etc/threshold.conf etc/snort.conf etc/generators \
	   $RPM_BUILD_ROOT/etc/snort
	find contrib -type f -exec chmod 0644 {} \;
	find contrib -type d -exec chmod 0755 {} \;
	find doc -type f -maxdepth 1 -not -name 'Makefile*' -exec install -p -m 0644 {} $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc \;
	find doc/signatures -type f -maxdepth 1 -not -name 'Makefile*' -exec install -p -m 0644 {} $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc/signatures \;

	rm -f $RPM_BUILD_ROOT%{_docdir}/%{name}-%{version}/doc/Makefile.*
    fi
}

# Fix the RULE_PATH
sed -e 's;var RULE_PATH ../rules;var RULE_PATH %{SnortRulesDir};' \
	< etc/snort.conf > etc/snort.conf.new
rm -f etc/snort.conf
mv etc/snort.conf.new etc/snort.conf

# Always install snort-plain
InstallSnort plain

# Maybe install the others
%if %{mysql}
  InstallSnort mysql
%endif

%if %{postgresql}
  InstallSnort postgresql
%endif

%if %{oracle}
  InstallSnort oracle
%endif


%clean
if [ -d $RPM_BUILD_ROOT ] && [ "$RPM_BUILD_ROOT" != "/" ]; then
	rm -rf $RPM_BUILD_ROOT
fi


%pre
# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	groupadd snort 2> /dev/null || true
	useradd -M -d %{_var}/log/snort -s /bin/false -c "Snort" -g snort snort 2>/dev/null || true
fi

%post mysql
if [ -L %{_sbindir}/snort ] || [ ! -e %{_sbindir}/snort ] ; then 
  rm -f %{_sbindir}/snort; ln -sf %{_sbindir}/snort-mysql %{_sbindir}/snort
fi

%post postgresql
if [ -L %{_sbindir}/snort ] || [ ! -e %{_sbindir}/snort ] ; then 
   rm -f %{_sbindir}/snort; ln -sf %{_sbindir}/snort-postgresql %{_sbindir}/snort
fi

%post oracle
if [ -L %{_sbindir}/snort ] || [ ! -e %{_sbindir}/snort ] ; then
   rm -f %{_sbindir}/snort; ln -sf %{_sbindir}/snort-oracle %{_sbindir}/snort
fi

%post
# Make a symlink if there is no link for snort-plain
if [ -L %{_sbindir}/snort ] || [ ! -e %{_sbindir}/snort ] ; then \
	rm -f %{_sbindir}/snort; ln -sf %{_sbindir}/snort-plain %{_sbindir}/snort; fi

# We should restart it to activate the new binary if it was upgraded
/etc/init.d/snortd condrestart 1>/dev/null 2>/dev/null

# Don't do all this stuff if we are upgrading
if [ $1 = 1 ] ; then
	chown -R snort.snort /var/log/snort
	/sbin/chkconfig --add snortd
fi



%preun
if [ $1 = 0 ] ; then
	# We get errors about not running, but we don't care
	/etc/init.d/snortd stop 2>/dev/null 1>/dev/null
	/sbin/chkconfig --del snortd
fi

%postun
# Try and restart, but don't bail if it fails
if [ $1 -ge 1 ] ; then
       /etc/init.d/snortd condrestart  1>/dev/null 2>/dev/null || :
fi

# Only do this if we are actually removing snort
if [ $1 = 0 ] ; then
   if [ -L %{_sbindir}/snort ]; then rm -f %{_sbindir}/snort; fi
   /usr/sbin/userdel snort 2>/dev/null
fi

%postun mysql
if [ -L %{_sbindir}/snort ]; then 
   rm -f %{_sbindir}/snort
   ln -sf %{_sbindir}/snort-plain %{_sbindir}/snort
fi

%postun postgresql
if [ -L %{_sbindir}/snort ]; then 
   rm -f %{_sbindir}/snort
   ln -sf %{_sbindir}/snort-plain %{_sbindir}/snort
fi

%postun oracle
if [ -L %{_sbindir}/snort ]; then 
   rm -f %{_sbindir}/snort
   ln -sf %{_sbindir}/snort-plain %{_sbindir}/snort
fi

%files
%defattr(-,root,root)
%attr(0755,root,root) %{_sbindir}/snort-plain
%attr(0644,root,root) %{_mandir}/man8/snort.8.gz
%attr(0755,root,root) %dir %{SnortRulesDir}
%attr(0644,root,root) %{SnortRulesDir}/*.rules
%attr(0644,root,root) %config(noreplace) /etc/snort/classification.config
%attr(0644,root,root) %config(noreplace) /etc/snort/reference.config
%attr(0644,root,root) %config(noreplace) /etc/snort/threshold.conf
%attr(0644,root,root) %config(noreplace) /etc/snort/*.map
%attr(0644,root,root) %config(noreplace) /etc/snort/generators
%attr(0644,root,root) %config(noreplace) /etc/logrotate.d/snort
%attr(0644,root,root) %config(noreplace) /etc/snort/snort.conf
%attr(0644,root,root) %config(noreplace) /etc/sysconfig/snort
%attr(0755,root,root) %config(noreplace) /etc/init.d/snortd
%attr(0755,snort,snort) %dir %{_var}/log/snort
%attr(0755,root,root) %dir /etc/snort
%dir %{_docdir}/%{name}-%{version}
%docdir %{_docdir}/%{name}-%{version}
%attr(0755,root,root) %{_docdir}/%{name}-%{version}/*

%if %{mysql}
%files mysql
%attr(0755,root,root) %{_sbindir}/snort-mysql
%endif

%if %{postgresql}
%files postgresql
%attr(0755,root,root) %{_sbindir}/snort-postgresql
%endif

%if %{oracle}
%files oracle
%attr(0755,root,root) %{_sbindir}/snort-oracle
%endif


################################################################
# Thanks to the following for contributions to the Snort.org SPEC file:
#       Henri Gomez <gomez@slib.fr>
#       Chris Green <cmg@sourcefire.com>
#       Karsten Hopp <karsten@redhat.de>
#       Tim Powers <timp@redhat.com>
#       William Stearns <wstearns@pobox.com>
#       Hugo van der Kooij <hugo@vanderkooij.org>
#       Wim Vandersmissen <wim@bofh.be>
#       Dave Wreski <dave@linuxsecurity.com>
#       JP Vossen <jp@jpsdomain.org>
#       Dainel Wittenberg <daniel-wittenberg@starken.com>

%changelog
* Thu Nov 17 2004 Brian Caswell <bmc@snort.org>
- handle the moving of RPM and the axing of contrib

* Sat Jun 03 2004 JP Vossen <jp@jpsdomain.org>
- Bugfix for 'snortd condrestart' redirect to /dev/null in %postun

* Wed May 12 2004 JP Vossen <jp@jpsdomain.org>
- Added code for cAos autobuilder
- Added buildrequires and requires for libpcap

* Thu May 06 2004 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Added JP's stats option to the standard rc script

* Sat Mar 06 2004 JP Vossen <jp@jpsdomain.org>
- Added gen-msg.map and sid-msg.map to /etc/snort

* Sat Feb 07 2004 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Applied postun/snortd patches from Nick Urbanik <nicku@vtc.edu.hk

* Mon Dec 22 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Added threshold.conf, unicode.map and generators to /etc/snort thanks
- 	to notes from Nick Urbanik <nicku@vtc.edu.hk>

* Sat Dec 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.1.0-2
- Added condrestart option to rc script from patch by
-       Nick Urbanik <nicku@vtc.edu.hk>
- Fixed condrestart bug for installs
- Fixed gzip bug that happens on some builds

* Tue Dec 10 2003 JP Vossen <jp@jpsdomain.org>
- Removed flexresp from plain rpm package description
- Added a line about pcre to the package description
- Trivial tweaks to package description

* Sat Nov 29 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.1.0-1
- Applied some updates from rh0212ms@arcor.de
- Applied some updates from Torsten Schuetze <torsten.schuetze@siemens.com>
- Applied some updates from Nick Urbanik <nicku@vtc.edu.hk>
- Fixed ALERTMODE rc script error reported by DFarino@Stamps.com
- Fixed CONF rc script error reported by ??
- Gzip signature files to save some space
- Added BuildRequires pcre-devel and Requires pcre
- Re-did %post <package> sections so the links are added and removed
-	correctly when you add/remove various packages 

* Fri Nov 07 2003 Daniel WIttenberg <daniel-wittenberg@starken.com> 
- Updated snort.logrotate

* Thu Nov 06 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.4
- Minor updates for 2.0.4

* Tue Nov 04 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.3
- Updated for 2.0.3
- Removed 2.0.2 patch
- Remove flexresp2 as it caused too many build problems and doesn't work
-       cleanly with 2.0.3 anyway
- Minor documentation updated for 2.0.3

* Mon Oct 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-6
- New release version
- Changed /etc/rc.d/init.d to /etc/init.d for more compatibility

* Fri Oct 17 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Changed as many hard-coded references to programs and paths to use
- 	standard defined macros

* Fri Oct 10 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Include SnortRulesDir in %%files section
- Added classification.config and reference.config in %%files section
- Minor cleanup of the for_fedora macro

* Sat Oct 04 2003 Dainel Wittenberg <daniel-wittenberg@starken.com> 
- Nuked post-install message as it caused too many problems
- Changed default ruledir to /etc/snort/rules
- Fixed problem with non-snort-plain symlinks getting created

* Fri Oct 03 2003 Dainel Wittenberg <daniel-wittenberg@starken.com> 
- Somehow the snort.logrotate cvs file got copied into the build tree
-	and the wrong file got pushed out
- snort.logrotate wasn't included in the %%files section, so added
-	it as a config(noreplace) file

* Thu Oct 02 2003 Dainel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-5
- Added --with fedora for building Fedora RPM's
- Removed references to old snort config patch
- Added noreplace option to /etc/rc.d/init.d/snortd just in case
- Gzip the man page to save (a small tiny) amount of space and make it
-	more "standard"
- Added version number to changelog entries to denote when packages were
-       released

* Wed Oct 01 2003 Dainel Wittenberg <daniel-wittenberg@starken.com>
- Fixed permission problem with /etc/snort being 644
- Added noreplace option to /etc/sysconfig/snort

* Fri Sep 26 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Fixed incorrect Version string in cvs version of the spec
- Added snort logrotate file
- Removed |more from output as it confuses some package managers

* Fri Sep 23 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-4
- Released 2.0.2-3 and then 2.0.2-4

* Sat Sep 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Added --with flexresp2 build option

* Fri Sep 19 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-2
- Gave into JP and changed version back to stable :)

* Fri Sep 19 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Fixed problems in snortd with "ALL" interfaces working correctly
- Removed history from individual files as they will get too big
- 	and unreadable quickly

* Thu Sep 18 2003 Daniel Wittenberg <daniel-wittenberg@starken.com> 2.0.2-1
- Updated for 2.0.2 and release 2.0.2-1 

* Tue Aug 26 2003 JP Vossen <jp@jpsdomain.org>
- Added code to run autojunk.sh for CVS tarball builds

* Mon Aug 25 2003 JP Vossen <jp@jpsdomain.org>
- Added missing comments to changelog

* Sun Aug 20 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Moved snortd and snortd.sysconfig to contrib/rpm
- Changed contrib install to a cp -a so the build stops complaining

* Mon Aug 11 2003 JP Vossen <jp@jpsdomain.org>
- Removed the commented patch clutter and a TO DO note
- Fussed with white space

* Sun Aug 10 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- Fixed a couple minor install complaints
- userdel/groupdel added back into %%postun
- useradd/groupadd added to %%pre

* Sat Aug  9 2003 JP Vossen <jp@jpsdomain.org>
- Doubled all percent signs in this changelog due to crazy RH9 RPM bug.
-     http://www.fedora.us/pipermail/fedora-devel/2003-June/001561.html
-     http://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=88620
- Turn off rpm debug due to RH9 RPM issue
-     http://www.cs.helsinki.fi/linux/linux-kernel/2003-15/0763.html
- Removed unnecessary SourceX: since they will be in the tarball

* Thu Aug  7 2003 JP Vossen <jp@jpsdomain.org>
- Changed perms from 755 to 644 for %%{_mandir}/man8/snort.8*

* Sun Aug  3 2003 JP Vossen <jp@jpsdomain.org>
- Removed the conf patch (again) as we moved the funcationality
- Added sed to buildrequires and sed it to fix RULE_PATH
- Removed Dan's SPEC code that made a default sysconfig/snort file.

* Sun Aug  3 2003 JP Vossen <jp@jpsdomain.org>
- Trivial changes and additions to documentation and references
- Added --with flexresp option
- Changed libnet buildrequires per Chris
- Added docs and contrib back in, and moved sig docs out of doc.
- Moved CSV and signature 'fixes' into %%install where they should have
-     been. Also fixed them.
- Added Dan's new snortd and snort.sysconfig
- Commented out alternate method of creating /etc/sysconfig/snort
- Created %%{OracleHome}
- Added BuildRequires: findutils
- Uncommented the patch and added the patch file

* Fri Jul 26 2003 Daniel Wittenberg <daniel-wittenberg@starken.com>
- commented out the patch for now since it doesn't exist
- if doing a new install echo "INTERFACE=eth0" > /etc/sysconfig/snort
- changed --with-libpcap-includes=/usr/include/pcap to /usr/include since
-     that is where the libpcap-snort rpm Chris sent puts things
- added missing " at the end of the SNORT_BASE_CONFIG
- minor change to the ./configure for plain so it actually works
- during an rpm -e of snort do a rm -f to make it a little more quiet in
-     case of problems
- massive re-write of multi-package build system
- initial support for compiling with Oracle

* Sun Jul 20 2003 JP Vossen <jp@jpsdomain.org>
- Took over maintenance of Snort.org RPM releases just before v2.0.1
- Various cleanup of SPEC file and changes to support building from tarball
- Removed some old packages (like SNMP and Bloat), per Chris
- First attempt at using --with option for multi-package build system
- Added a patch to snort.conf for $RULE_PATH and default output plugins

* Wed Sep 25 2002 Chris Green <cmg@sourcefire.com>
- updated to 1.9.0

* Tue Nov  6 2001 Chris Green <cmg@uab.edu>
- merged in Hugo's changes
- updated to 1.8.3
- fixing symlinks on upgrades

* Tue Nov  6 2001 Hugo van der Kooij <hugo@vanderkooij.org>
- added libpcap to the list as configure couldn't find it on RedHat 7.2
- added several packages to the build requirements

* Fri Nov  2 2001 Chris Green <cmg@uab.edu>
- updated to 1.8.2-RELEASE
- adding SQL defines
- created tons of packages so that all popular snort configs are accounted for

* Sat Aug 18 2001 Chris Green <cmg@uab.edu>
- 1.8.1-RELEASE
- cleaned up enough to release to general public

* Tue May  8 2001 Chris Green <cmg@uab.edu>
- moved to 1.8cvs
- changed rules files
- removed initial configuration

* Mon Nov 27 2000 Chris Green <cmg@uab.edu>
- removed strip
- upgrade to cvs version
- moved /var/snort/dev/null creation to install time

* Tue Nov 21 2000 Chris Green <cmg@uab.edu>
- changed to %%{SnortPrefix}
- upgrade to patch2

* Mon Jul 31 2000 Wim Vandersmissen <wim@bofh.st>
- Integrated the -t (chroot) option and build a /home/snort chroot jail
- Installs a statically linked/stripped snort
- Updated /etc/rc.d/init.d/snortd to work with the chroot option

* Tue Jul 25 2000 Wim Vandersmissen <wim@bofh.st>
- Added some checks to find out if we're upgrading or removing the package

* Sat Jul 22 2000 Wim Vandersmissen <wim@bofh.st>
- Updated to version 1.6.3
- Fixed the user/group stuff (moved to %%post)
- Added userdel/groupdel to %%postun
- Automagically adds the right IP, nameservers to /etc/snort/rules.base

* Sat Jul 08 2000 Dave Wreski <dave@linuxsecurity.com>
- Updated to version 1.6.2
- Removed references to xntpd
- Fixed minor problems with snortd init script

* Fri Jul 07 2000 Dave Wreski <dave@linuxsecurity.com>
- Updated to version 1.6.1
- Added user/group snort

* Sat Jun 10 2000 Dave Wreski <dave@linuxsecurity.com>
- Added snort init.d script (snortd)
- Added Dave Dittrich's snort rules header file (ruiles.base)
- Added Dave Dittrich's wget rules fetch script (check-snort)
- Fixed permissions on /var/log/snort
- Created /var/log/snort/archive for archival of snort logs
- Added post/preun to add/remove snortd to/from rc?.d directories
- Defined configuration files as %%config

* Tue Mar 28 2000 William Stearns <wstearns@pobox.com>
- Quick update to 1.6.
- Sanity checks before doing rm-rf in install and clean

* Fri Dec 10 1999 Henri Gomez <gomez@slib.fr>
- 1.5-0 Initial RPM release

