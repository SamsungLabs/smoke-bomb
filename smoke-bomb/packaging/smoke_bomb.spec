Name: smoke_bomb
Version: 0
Release: 0
License: To be filled
Summary: smoke-bomb
Packager: Jinbum Park <jinb.park@samsung.com>
Group: Application
Source: %{name}-%{version}.tar.gz
BuildRequires: cmake
BuildRequires: pkgconfig(tztv-hawk-kmodules)

%description
Platform Project

%prep
%setup -q

%build
cmake .
make

cd lkm
./build.sh

%install
rm -rf %{buildroot}

mkdir -p $RPM_BUILD_ROOT/usr/bin/
cp -f packaging/smoke_bomb.ko $RPM_BUILD_ROOT/usr/bin/
#cp -f bin/sb_test $RPM_BUILD_ROOT/usr/bin/

%clean

%files
%defattr(-, root, root, -)
/usr/bin/*

%changelog
* Sat Mar 24 2012 Author <E-mail>
 - initial release
