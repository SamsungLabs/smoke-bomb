#!/bin/sh

CC=armv7l-tizen-linux-gnueabi-

# build lkm
cd lkm

cp -f Makefile Makefile.bkg
cp -f Makefile.local Makefile
sync

make CROSS_COMPILE=${CC} ARCH=arm

cp -f Makefile.bkg Makefile
rm -f Makefile.bkg
sync
cd ../

# build sb_api
cd lib/
${CC}gcc -g -O0 -D_SMOKE_BOMB_ARMV7 -c -o sb_api.o sb_api.c
${CC}ar rcs libsb_api.a sb_api.o
cd ../

# build sb_test
cd test
${CC}gcc -g -O0 -D_SMOKE_BOMB_ARMV7 -I./../../lib/libflush/libflush -L./../../lib/libflush/build/armv7/release -L./../lib/ -o sb_test sb_test.c -lsb_api -lflush
cd ../

# make build dir
mkdir build
cp -f lkm/smoke_bomb.ko build/
cp -f test/sb_test build/




