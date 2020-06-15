#!/bin/sh

# clean lkm

cd lkm
rm -rf *.o *.ko *.mod *.symvers *.order *.mod.c .*cmd .tmp*
cd ../

cd arm64
rm -rf *.o .*cmd
cd ../

# clean api
cd lib
rm -f *.o *.a
cd ../

# clean test
cd test
rm -f sb_test
cd ../

# clean build/
rm -rf build


