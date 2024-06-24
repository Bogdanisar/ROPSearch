#!/bin/bash


# Run this from the ROOP/deps folder!
deps_folder=$(pwd)

# STEP_BY_STEP_INSTALL <- set this variable to make the script wait for a keypress before executing the next step in the build process.
echo STEP_BY_STEP_INSTALL is "$STEP_BY_STEP_INSTALL"
echo

ASK_TO_PROCEED () {
	if [ -n "$STEP_BY_STEP_INSTALL" ]; then
		echo
		echo Press any key to move to the next step.
		read -n 1 -s
	fi;
}


# Install keystone for a *nix OS.
set -x

sudo apt-get install cmake
set +x; ASK_TO_PROCEED; set -x;

cd "$deps_folder"
set +x; ASK_TO_PROCEED; set -x;

mkdir -p keystone/build
cd keystone/build
set +x; ASK_TO_PROCEED; set -x;

# Build keystone as a static library, with debug information included.
../make-lib.sh debug
set +x; ASK_TO_PROCEED; set -x;

# Install keystone
sudo make install
