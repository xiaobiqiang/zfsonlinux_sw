#!/bin/bash

cp module/Makefile_centos.in module/Makefile.in
./autogen.sh
./configure --with-spl=$1
make && make install
