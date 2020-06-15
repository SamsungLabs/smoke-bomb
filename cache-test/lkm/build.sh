#!/bin/bash

# debug build
make CROSS_COMPILE=""
cp -f cache.ko ../packaging/
make CROSS_COMPILE="" clean

