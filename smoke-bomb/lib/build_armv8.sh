#!/bin/sh

aarch64-linux-gnu-gcc -g -D_SMOKE_BOMB_ARMV8 -O0 -fPIC -c -o sb_api.o sb_api.c
aarch64-linux-gnu-ar rcs libsb_api.a sb_api.o
