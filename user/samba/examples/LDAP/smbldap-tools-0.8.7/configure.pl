#!/usr/bin/perl -w

# $Id: configure.pl,v 1.13 2004/06/25 20:57:51 jtournier Exp $
# $Source: /opt/cvs/samba/smbldap-tools/configure.pl,v $

# This script can help you setting up the smbldap_conf.pl file. It will get all the defaults value
# that are defined in the smb.conf configuration file. You should then start with this configuration
# file. You will also need the SID for your samba domain: set up the controler domain before using
# this script.

#  This code was developped by IDEALX (http://IDEALX.org/) and
#  contributors (their names can be found in the CONTRIBUTORS file).
#
#                 Copyright (C) 2002 IDEALX
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU General Public License
#  as published by the Free Software Foundation; either version 2
#  of the License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307,
#  USA.


use strict;

# we need to be root to configure the scripts
if ($< != 0) {
	die "Only root can configure the smbldap-tools scripts\n";
}

print "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-
       smbldap-tools script configuration
       -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
Before starting, check
 . if your samba controller is up and running.
 . if the domain SID is defined (you can get it with the 'net getlocalsid')

 . you can leave the configuration using the Crtl-c key combination
 . empty value can be set with the \".\" caracter\n";
print "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-\n";
print "Looking for configuration files...\n\n";
my $smb_conf;
if (-e "/etc/samba/smb.conf") {
	$smb_conf="/etc/samba/smb.conf";
} elsif (-e "/usr/local/samba/lib/smb.conf") {
	$smb_conf="/usr/local/samba/lib/smb.conf";
}
print "Samba Config File Location [$smb_conf] > ";
chomp(my $config_smb=<STDIN>);
if ($config_smb ne "") {
	$smb_conf=$config_smb;
}
my $smbldap_conf;
if (-e "/etc/smbldap-tools/smbldap.conf") {
	$smbldap_conf="/etc/smbldap-tools/smbldap.conf";
}
print "smbldap Config file Location (global parameters) [$smbldap_conf] > ";
chomp(my $config_smbldap=<STDIN>);
if ($config_smbldap ne "") {
        $smbldap_conf=$config_smbldap;
}

my $smbldap_bind_conf;
if (-e "/etc/smbldap-tools/smbldap_bind.conf") {
	$smbldap_bind_conf="/etc/smbldap-tools/smbldap_bind.conf";
}
print "smbldap Config file Location (bind parameters) [$smbldap_bind_conf] > ";
chomp(my $config_smbldap_bind=<STDIN>);
if ($config_smbldap_bind ne "") {
        $smbldap_bind_conf=$config_smbldap_bind;
}


# Let's read the smb.conf configuration file
my %config;
open (CONFIGFILE, "$smb_conf") || die "Unable to open $smb_conf for reading !\n";

while (<CONFIGFILE>) {

        chomp($_);

        ## eat leading whitespace
        $_=~s/^\s*//;

        ## eat trailing whitespace
        $_=~s/\s*$//;


        ## throw away comments
        next if (($_=~/^#/) || ($_=~/^;/));

        ## check for a param = value
        if ($_=~/=/) {
                #my ($param, $value) = split (/=/, $_);
                my ($param, $value) = ($_=~/([^=]*)=(.*)/i);
                $param=~s/./\l$&/g;
                $param=~s/\s+//g;
                $value=~s/^\s+//;

		$value=~s/"//g;

                $config{$param} = $value;
		#print "param=$param\tvalue=$value\n";

                next;
        }
}
close (CONFIGFILE);

print "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";
print "Let's start configuring the smbldap-tools scripts ...\n\n";

# This function need 3 parameters:
# . the description of the parameter
# . the defaut value of the parameter or the name of the key it is related to in the %config hash
#   you can get all the available keys using this:
#   foreach my $tmp (keys %config) {
#	print "key=$tmp\t value=$config{$tmp}\n";
#   }
# . the 'insist' variable: if set to 1, then the script will always call for a value
#   for the parameter. In other words, there's not default value, and it can't be set
#   to a null caracter string.

sub read_entry
{
	my $description=shift;
	my $value=shift;
	my $insist=shift;
	my $value_tmp;
	chomp($value);
	$insist=0 if (! defined $insist);
			if (defined $config{$value}) {
				print "$description [$config{$value}] > ";
				$value_tmp=$config{$value};
			} else {
				print "$description [$value] > ";
				$value_tmp="$value";
			}
			chomp(my $get=<STDIN>);
			if ($get eq "") {
				$value=$value_tmp;
			} elsif ($get eq ".") {
				$value="";
			} else {
				$value=$get;
			}
	if ($insist == 1 and "$value" eq "") {
		while ($insist == 1) {
			print "  Warning: You really need to set this parameter...\n";
			$description=~s/. /  /;
			if (defined $config{$value}) {
				print "$description [$config{$value}] > ";
				$value_tmp=$config{$value};
			} else {
				print "$description [$value] > ";
				$value_tmp="$value";
			}
			chomp(my $get=<STDIN>);
			if ($get eq "") {
				$value=$value_tmp;
			} elsif ($get eq ".") {
                                $value="";
                        } else {
				$value=$get;
				$insist=0;
			}
		}
	}
	return $value;
}

print ". workgroup name: name of the domain Samba act as a PDC\n";
my $workgroup=read_entry("  workgroup name","workgroup",0);

print ". netbios name: netbios name of the samba controler\n";
my $netbios_name=read_entry("  netbios name","netbiosname",0);

print ". logon drive: local path to which the home directory will be connected (for NT Workstations). Ex: 'H:'\n";
my $logondrive=read_entry("  logon drive","logondrive",0);

print ". logon home: home directory location (for Win95/98 or NT Workstation).\n  (use %U as username) Ex:'\\\\$netbios_name\\home\\%U'\n";
my $logonhome=read_entry("  logon home (leave blank if you don't want homeDirectory)","\\\\$netbios_name\\home\\%U",0);
#$logonhome=~s/\\/\\\\/g;

print ". logon path: directory where roaming profiles are stored. Ex:'\\\\$netbios_name\\profiles\\\%U'\n";
my $logonpath=read_entry("  logon path (leave blank if you don't want roaming profile)","\\\\$netbios_name\\\profiles\\\%U",0);
#$logonpath=~s/\\/\\\\/g;

my $userHome=read_entry(". home directory prefix (use %U as username)","/home/\%U",0);

my $userScript=read_entry(". default user netlogon script (use %U as username)","\%U.cmd",0);

my $defaultMaxPasswordAge=read_entry("  default password validation time (time in days)","45",0);

#############################
# ldap directory parameters #
#############################
my $ldap_suffix=read_entry(". ldap suffix","ldapsuffix",0);
my $ldap_group_suffix=read_entry(". ldap group suffix","ldapgroupsuffix",0);
$ldap_group_suffix=~s/ou=//;
my $ldap_user_suffix=read_entry(". ldap user suffix","ldapusersuffix",0);
$ldap_user_suffix=~s/ou=//;
my $ldap_machine_suffix=read_entry(". ldap machine suffix","ldapmachinesuffix",0);
$ldap_machine_suffix=~s/ou=//;
my $ldap_idmap_suffix=read_entry(". Idmap suffix","ldapidmapsuffix",0);
print ". sambaUnixIdPooldn: object where you want to store the next uidNumber\n";
print "  and gidNumber available for new users and groups\n";
my $sambaUnixIdPooldn=read_entry("  sambaUnixIdPooldn object (relative to \${suffix})","cn=NextFreeUnixId",0);

# parameters for the master ldap server
my ($trash1,$server);
if (defined $config{passdbbackend}) {
	($trash1,$server)=($config{passdbbackend}=~m/(.*)ldap:\/\/(.*)\//);
} else {
	$server="127.0.0.1";
}
my $ldapmasterserver;
print ". ldap master server: IP adress or DNS name of the master (writable) ldap server\n";
$ldapmasterserver=read_entry("  ldap master server",$server,0);
my $ldapmasterport;
if (defined $config{ldapport}) {
	$ldapmasterport=read_entry(". ldap master port","ldapport",0);
} else {
	$ldapmasterport=read_entry(". ldap master port",389,0);
}
my $ldap_master_admin_dn=read_entry(". ldap master bind dn","ldapadmindn",0);
system "stty -echo";
my $ldap_master_bind_password=read_entry(". ldap master bind password","",1);
print "\n";
system "stty echo";

# parameters for the slave ldap server
print ". ldap slave server: IP adress or DNS name of the slave ldap server: can also be the master one\n";
my $ldap_slave_server=read_entry("  ldap slave server",$server,0);
my $ldap_slave_port;
if (defined $config{ldapport}) {
	$ldap_slave_port=read_entry(". ldap slave port","ldapport",0);
} else {
	$ldap_slave_port=read_entry(". ldap slave port","389",0);
}
my $ldap_slave_admin_dn=read_entry(". ldap slave bind dn","ldapadmindn",0);
system "stty -echo";
my $ldap_slave_bind_password=read_entry(". ldap slave bind password","",1);
print "\n";
system "stty echo";
my $ldaptls=read_entry(". ldap tls support (1/0)","0",0);
my ($cert_verify,$cert_cafile,$cert_clientcert,$cert_clientkey);
if ($ldaptls == 1) {
	$cert_verify=read_entry(". How to verify the server's certificate (none, optional or require)","require",0);
	$cert_cafile=read_entry(". CA certificate file","/etc/smbldap-tools/ca.pem",0);
	$cert_clientcert=read_entry(". certificate to use to connect to the ldap server","/etc/smbldap-tools/smbldap-tools.pem",0);
	$cert_clientkey=read_entry(". key certificate to use to connect to the ldap server","/etc/smbldap-tools/smbldap-tools.key",0);
}

# let's test if any sid is available
my $sid_tmp=`net getlocalsid \$netbios_name 2>/dev/null | cut -f2 -d: | sed "s/ //g"`;
print ". SID for domain $config{workgroup}: SID of the domain (can be obtained with 'net getlocalsid $netbios_name')\n";
my $sid=read_entry("  SID for domain $config{workgroup}",$sid_tmp,0);

print ". unix password encryption: encryption used for unix passwords\n";
my $cryp_algo=read_entry("  unix password encryption (CRYPT, MD5, SMD5, SSHA, SHA)","SSHA",0);
my $crypt_salt_format;
if ( $cryp_algo eq "CRYPT" ) {
  print ". crypt salt format: If hash_encrypt is set to CRYPT, you may set \n";
  print "  a salt format. The default is \"%s\", but many systems will generate\n";
  print "  MD5 hashed passwords if you use \"\$1\$\%\.8s\"\n";
  $crypt_salt_format=read_entry("  crypt salt format","%s",0);
}

my $default_user_gidnumber=read_entry(". default user gidNumber","513",0);

my $default_computer_gidnumber=read_entry(". default computer gidNumber","515",0);

my $userLoginShell=read_entry(". default login shell","/bin/bash",0);

my $mailDomain=read_entry(". default domain name to append to mail adress", "",0);

### Let's now incorporate our modifications
open (SMBLDAP, "$smbldap_conf") || die "Unable to open $smbldap_conf for reading!\n";
my $lines;
my $begin_parameter=0;
while (my $line=<SMBLDAP>) {
	chomp($line);
	if ($line =~ m /# General Configuration/) {
		$begin_parameter=1;
	}
	if ($begin_parameter == 1) {
               $line="SID=\"$sid\"" if ($line=~m/^SID/);
                $line="slaveLDAP=\"$ldap_slave_server\"" if ($line=~m/^slaveLDAP/);
                $line="slavePort=\"$ldap_slave_port\"" if ($line=~m/^slavePort/);
                $line="masterLDAP=\"$ldapmasterserver\"" if ($line=~m/^masterLDAP/);
                $line="masterPort=\"$ldapmasterport\"" if ($line=~m/^masterPort/);
                $line="ldapTLS=\"$ldaptls\"" if ($line=~m/^ldapTLS/);
		if ($ldaptls == 1) {
	                $line="verify=\"$cert_verify\"" if ($line=~m/^verify/);
        	        $line="cafile=\"$cert_cafile\"" if ($line=~m/^cafile/);
                	$line="clientcert=\"$cert_clientcert\"" if ($line=~m/^clientcert/);
	                $line="clientkey=\"$cert_clientkey\"" if ($line=~m/^clientkey/);
		} else {
	                $line="verify=\"\"" if ($line=~m/^verify/);
        	        $line="cafile=\"\"" if ($line=~m/^cafile/);
                	$line="clientcert=\"\"" if ($line=~m/^clientcert/);
	                $line="clientkey=\"\"" if ($line=~m/^clientkey/);
		}
                $line="suffix=\"$ldap_suffix\"" if ($line=~m/^suffix/);
                $line="usersdn=\"ou=$ldap_user_suffix,\${suffix}\"" if ($line=~m/^usersdn/);
                $line="computersdn=\"ou=$ldap_machine_suffix,\${suffix}\"" if ($line=~m/^computersdn/);
                $line="groupsdn=\"ou=$ldap_group_suffix,\${suffix}\"" if ($line=~m/^groupsdn/);
                $line="idmapdn=\"$ldap_idmap_suffix,\${suffix}\"" if ($line=~m/^idmap/);
                $line="sambaUnixIdPooldn=\"$sambaUnixIdPooldn,\${suffix}\"" if ($line=~m/^sambaUnixIdPooldn/);
                $line="hash_encrypt=\"$cryp_algo\"" if ($line=~m/^hash_encrypt/);
                $line="crypt_salt_format=\"$crypt_salt_format\"" if (defined($crypt_salt_format) && $line=~m/^?(\s)*crypt_salt_format/);
                $line="userHome=\"$userHome\"" if ($line=~m/^userHome\s*=/);
                $line="defaultUserGid=\"$default_user_gidnumber\"" if ($line=~m/^defaultUserGid/);
                $line="defaultComputerGid=\"$default_computer_gidnumber\"" if ($line=~m/^defaultComputerGid/);
                $line="defaultMaxPasswordAge=\"$defaultMaxPasswordAge\"" if ($line=~m/^defaultMaxPasswordAge/);
                $line="userLoginShell=\"$userLoginShell\"" if ($line=~m/^userLoginShell/);
                $line="userSmbHome=\"$logonhome\"" if ($line=~m/^userSmbHome/);
                $line="userScript=\"$userScript\"" if ($line=~m/^userScript/);
                $line="mailDomain=\"$mailDomain\"" if ($line=~m/^mailDomain/);
                $line="userProfile=\"$logonpath\"" if ($line=~m/^userProfile/);
                $line="userHomeDrive=\"$logondrive\"" if ($line=~m/^userHomeDrive/);
	}
	$lines.="$line\n";
}
close(SMBLDAP);

open (SMBLDAP_BIND, "$smbldap_bind_conf") || die "Unable to open $smbldap_bind_conf for reading!\n";
my $lines_bind;
while (my $line_bind=<SMBLDAP_BIND>) {
	chomp($line_bind);
	$line_bind="masterDN=\"$ldap_master_admin_dn\"" if ($line_bind=~m/^masterDN/);
	$line_bind="masterPw=\"$ldap_master_bind_password\"" if ($line_bind=~m/^masterPw/);
	$line_bind="slaveDN=\"$ldap_slave_admin_dn\"" if ($line_bind=~m/^slaveDN/);
	$line_bind="slavePw=\"$ldap_slave_bind_password\"" if ($line_bind=~m/^slavePw/);
	$lines_bind.="$line_bind\n";
}
close(SMBLDAP_BIND);

print "-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n";

print "backup old configuration files:\n";
print "  $smbldap_conf->$smbldap_conf.old\n";
print "  $smbldap_bind_conf->$smbldap_bind_conf.old\n";
rename "$smbldap_conf","$smbldap_conf.old";
rename "$smbldap_bind_conf","$smbldap_bind_conf.old";

print "writing new configuration file:\n";
open (SMBLDAP,">$smbldap_conf") || die "Unable to open $smbldap_conf for writing !\n";
print SMBLDAP "$lines";
my $mode=0644;
chmod $mode,"$smbldap_conf","$smbldap_conf.old";
print "  $smbldap_conf done.\n";
close(SMBLDAP);

open (SMBLDAP_BIND,">$smbldap_bind_conf") || die "Unable to open $smbldap_bind_conf for writing !\n";
print SMBLDAP_BIND "$lines_bind";
$mode=0600;
chmod $mode,"$smbldap_bind_conf","$smbldap_bind_conf.old";
print "  $smbldap_bind_conf done.\n";
close(SMBLDAP_BIND);



