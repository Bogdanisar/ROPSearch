#!/bin/bash

# Change CWD to script location
cd "$(dirname "$0")"

./getInfoExec.sh /usr/lib32/libc.so.6 > ../bin/info32_libc.txt
./getInfoExec.sh /usr/lib32/ld-linux.so.2 > ../bin/info32_ld.txt

./getInfoExec.sh /usr/lib/x86_64-linux-gnu/libc.so.6 > ../bin/info64_libc.txt
./getInfoExec.sh /usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 > ../bin/info64_ld.txt
