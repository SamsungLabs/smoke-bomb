#!/bin/bash

# debug build
make CROSS_COMPILE=""
cp -f smoke_bomb.ko ../packaging/
make CROSS_COMPILE="" clean

