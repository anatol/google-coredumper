%define	ver	%VERSION
%define	RELEASE	1
%define rel     %{?CUSTOM_RELEASE} %{!?CUSTOM_RELEASE:%RELEASE}
%define	prefix	/usr

Name: %NAME
Summary: Generate a core dump of a running program without crashing
Version: %ver
Release: %rel
Group: Development/Libraries
URL: http://code.google.com/p/google-coredumper
License: BSD
Vendor: Google
Packager: Google <opensource@google.com>
Source: http://google-coredumper.googlecode.com/files/%{NAME}-%{PACKAGE_VERSION}.tar.gz
Distribution: Redhat 7 and above.
Buildroot: %{_tmppath}/%{name}-root
Prefix: %prefix

%description
The %name utility allows a running program to generate a core
file without actually crashing.  This serves to allow the programmer
to generate a snapshot of a running program's state at any time.

%package devel
Summary: Generate a core dump of a running program without crashing
Group: Development/Libraries
Requires: %{name} = %{version}

%description devel
The %name-devel package contains static and debug libraries and header
files for developing applications that use the %name utility.

%changelog
    * Thu Feb 15 2007 <opensource@google.com>
    - Added dependencies to devel RPMs
    - Added manual pages

    * Wed Feb 14 2007 <opensource@google.com>
    - Fixed compatibility with new RPM versions

    * Fri Feb 11 2005 <opensource@google.com>
    - First draft

%prep
%setup

%build
./configure
make prefix=%prefix

%install
rm -rf $RPM_BUILD_ROOT
make prefix=$RPM_BUILD_ROOT%{prefix} install

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)

%doc AUTHORS COPYING ChangeLog INSTALL NEWS README TODO examples

%{prefix}/lib/libcoredumper.so.0
%{prefix}/lib/libcoredumper.so.0.0.0


%files devel
%defattr(-,root,root)

%{prefix}/include/google
%{prefix}/lib/libcoredumper.a
%{prefix}/lib/libcoredumper.la
%{prefix}/lib/libcoredumper.so
%{prefix}/man/man3/GetCompressedCoreDump.3.gz
%{prefix}/man/man3/GetCoreDump.3.gz
%{prefix}/man/man3/WriteCompressedCoreDump.3.gz
%{prefix}/man/man3/WriteCoreDump.3.gz
%{prefix}/man/man3/WriteCoreDumpLimited.3.gz
