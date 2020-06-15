Name: cache_test
Version: 0.0.1
Release: 1
License: To be filled
Summary: helloworld application (unstripped)
Packager: Author <E-mail>
Group: Application
Source: %{name}-%{version}.tar.gz
BuildRequires: cmake
BuildRequires: pkgconfig(tztv-hawk-kmodules)

%description
Platform Project

%prep
%setup -q

%build
cd lkm
./build.sh

%install
rm -rf %{buildroot}

mkdir -p $RPM_BUILD_ROOT/usr/bin/
cp -f packaging/cache.ko $RPM_BUILD_ROOT/usr/bin/

%clean

%files
%defattr(-, root, root, -)
/usr/bin/*

%changelog
* Sat Mar 24 2012 Author <E-mail>
 - initial release
