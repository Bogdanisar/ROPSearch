#!/bin/bash

# set -x

# echo '______ Ubuntu version ______'
# lsb_release --all
# echo

# Get the executable path from the first argument to the script
execpath="$1"

echo '______ Binary version ______'
"$execpath" --version
echo

echo '______ Binary hash (MD5) ______'
md5sum "$execpath"
echo
