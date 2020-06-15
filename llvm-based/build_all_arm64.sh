#!/bin/sh

cd smokebomb-pass
./build.sh

cd ../src
./build_arm64.sh
cd ../
