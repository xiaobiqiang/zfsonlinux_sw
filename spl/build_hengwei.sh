#!/bin/bash

./autogen.sh
./configure --enable-hengwei=yes
make -j 16 && make install
