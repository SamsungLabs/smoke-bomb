#!/bin/sh

armv7l-tizen-linux-gnueabi-gcc -g -D_SMOKE_BOMB_ARMV7 -marm -fPIC -c -o sb_api.o sb_api.c
armv7l-tizen-linux-gnueabi-ar rcs libsb_api.a sb_api.o
