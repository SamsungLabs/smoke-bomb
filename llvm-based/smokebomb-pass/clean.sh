#!/bin/sh

find . -iwholename '*cmake*' -not -name CMakeLists.txt -delete
rm -f smokeBomb/*.so

