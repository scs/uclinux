%define name	tinylogin
%define epoch   0
%define version	1.4
%define release	%(date -I | sed -e 's/-/_/g')
%define serial  1

Name:	 %{name}
#Epoch:   %{epoch}
Version: %{version}
Release: %{release}
Serial:	 %{serial}
Copyright: GPL
Group: System/Utilities
Summary: A tiny utility suite for login and password handling.
URL:	 http://tinylogin.busybox.net/
Source:	 http://tinylogin.busybox.net/downloads/%{name}-%{version}.tar.gz
Buildroot: /var/tmp/%{name}-%{version}
Packager : Erik Andersen <andersen@codepoet.org>

%Description
TinyLogin is a suite of tiny utilities in a multi-call binary, which
enables your system to handle user authentication, and setting of
passwords. It is a drop-in to works nicely with BusyBox (another
multi-call binary), and makes an excellent addition to any small or
embedded system.

%Prep
%setup -q -n %{name}-%{version}

%Build
make

%Install
rm -rf $RPM_BUILD_ROOT
make PREFIX=$RPM_BUILD_ROOT install

%Clean
rm -rf $RPM_BUILD_ROOT

%Files 
%defattr(-,root,root)
/

