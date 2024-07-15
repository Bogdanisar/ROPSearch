#!/bin/bash


SCRIPT_PATH=$(realpath "${BASH_SOURCE[0]}")
DEPS_FOLDER=$(dirname "$SCRIPT_PATH")/

set -x

sudo apt-get update

echo




################### Install the Keystone framework for a *nix OS. ###################

printf "//////////////////////////// Installing the Keystone framework ////////////////////////////\n\n"

sudo apt-get install cmake

cd "$DEPS_FOLDER"

mkdir -p keystone/build
cd keystone/build

# Build keystone as a static library, with debug information included.
../make-lib.sh debug

# Install keystone
sudo make install

echo

################### Install the Keystone framework for a *nix OS. ###################




################### Install the Capstone framework for a *nix OS. ###################

printf "//////////////////////////// Installing the Capstone framework ////////////////////////////\n\n"

cd "$DEPS_FOLDER"/capstone

./make.sh

sudo ./make.sh install

sudo ldconfig

echo

################### Install the Capstone framework for a *nix OS. ###################
