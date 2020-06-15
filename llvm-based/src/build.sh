#!/bin/sh

clang -c -emit-llvm hello.c -o hello.bc
llvm-dis hello.bc -o -

#opt -load ../smokebomb-pass/smokeBomb/libsmokeBomb.so < hello.bc > /dev/null
#opt -load ../smokebomb-pass/smokeBomb/libsmokeBomb.so -help

# build library
clang -c -o libsb_api.o sb_api.c
llvm-ar rc libsb_api.a libsb_api.o

clang -g -Xclang -load -Xclang ../smokebomb-pass/smokeBomb/libsmokeBomb.so hello.c -L. -lsb_api

