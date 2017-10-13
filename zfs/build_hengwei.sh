#!/bin/bash

cp module/Makefile_hengwei.in module/Makefile.in
./autogen.sh
./configure --enable-hengwei=yes --with-spl=$1
make && make install
