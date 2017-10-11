#!/bin/bash

./autogen.sh
./configure --enable-hengwei=yes
make && make install
