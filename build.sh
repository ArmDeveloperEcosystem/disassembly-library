#!/bin/bash
#
# SPDX-FileCopyrightText: Copyright (C) 2024 Arm Limited and/or its affiliates
# SPDX-FileCopyrightText: <open-source-office@arm.com>
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License. You may obtain a copy
# of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
#
# Arm Disassembly Library build script.
#
# This script will checkout a fresh version of the LLVM source code, apply some
# modifications to provide additional functionality, then compile into a shared
# library. It will also build the example programs from the examples directory,
# the test programs from the test directory, and an installable Python package
# By default, the script will build all components, and remove any library
# build artifacts unless the -p option is specified. LLVM will always be
# re-built unless the -s option is specified.
#
# Examples:
#    Build the library and clean up build artifacts afterwards, using eight jobs:
#        ./build.sh -j 8
#    Build everything and preserve LLVM build artifacts afterwards:
#        ./build.sh -n
#    Build the library with debug symbols, clean up afterwards, but skip the LLVM build:
#        ./build.sh -d -s
#    Only build the LLVM part of the library:
#        ./build.sh -l
#    Only build the Python package:
#        ./build.sh -p
#

# Exit build script if any command fails
set -e

# Constants
LLVM_GIT_TAG=llvmorg-18.1.8
LLVM_TEMP_DIR=llvm-temp
LLVM_LIB_DIR=llvmlib
MAX_BUILD_JOBS=$(nproc --all)
PLATFORM=$(uname -s)

case $PLATFORM in
  Darwin)
    LIB_EXT=".dylib"
    ;;
  *)
    LIB_EXT=".so"
    ;;
esac

LIBARMDISASM=libarmdisasm$LIB_EXT

# Command-line arguments and defaults
BUILD_ALL=true
BUILD_DEBUG=false
BUILD_JOBS=$(( ($MAX_BUILD_JOBS+1)/2 ))
BUILD_LIB=false
BUILD_LLVM=false
NO_CLEANUP=false
BUILD_PYTHON=false
SKIP_LLVM_BUILD=false
UNIT_TESTS=false

usage()
{
    echo "A build script for the Arm Disassembly Library"
    echo ""
    echo "-a (lib)            Only build the Arm Disassembly Library, examples, and tests."
    echo "-d (debug)          Produce debug symbols during build"
    echo "-h (help)           Display usage"
    echo "-j (jobs)           Number of parallel worker jobs to use for building"
    echo "-l (llvm)           Only build LLVM and then stop"
    echo "-n (no-cleanup)     Don't clean up build artifacts (e.g. LLVM source/build files)"
    echo "-p (python)         Only build the installable Python package"
    echo "-s (skip-llvm)      Skip the LLVM part of the library build"
    echo "-t (tests)          Only run the unit tests"
}

calculate_build_jobs()
{
    jobs=$1

    # Prevent out-of-range values
    if [[ $jobs -le 0 || $jobs -gt $MAX_BUILD_JOBS ]]
    then
        jobs=$MAX_BUILD_JOBS
    fi

    echo $jobs
}

# Function to clone the LLVM source code from Git. Only use a shallow clone as
# we will delete it after the build is complete (unless -n option specified).
# Try to clone it three times before giving up.
clone_llvm()
{
    # Temporarily disable exit-on-error for the loop
    set +e
    iterations=3
    for ((i=1; i<=iterations; i++)); do
        # We want to exit-on-error if the last clone attempt fails.
        if [[ $i -eq $iterations ]]; then
            set -e
        fi

        # If running in a CI pipeline, use GitHub token to clone repo and enable
        # Git verbosity for debug purposes.
        GITHUB_HOST=github.com
        if [[ $CI = "true" ]]; then
            GITHUB_HOST=${GITHUB_TOKEN}@github.com
            GIT_CURL_VERBOSE=1 GIT_TRACE=1 git clone --depth 1 --branch $LLVM_GIT_TAG https://${GITHUB_HOST}/llvm/llvm-project.git $LLVM_TEMP_DIR
        else
            git clone --depth 1 --branch $LLVM_GIT_TAG https://${GITHUB_HOST}/llvm/llvm-project.git $LLVM_TEMP_DIR
        fi

        # Check if Git clone returned exit code 0.
        if [[ $? -eq 0 ]]; then
            break
        else
            slp=30
            echo "LLVM git clone failed on attempt $i"
            echo "Removing ${LLVM_TEMP_DIR}"
            rm -rf $LLVM_TEMP_DIR
            echo "Sleeping for ${slp}s before re-trying"
            sleep $slp
        fi
    done
    # Re-enable exit-on-error
    set -e
}

# Function to build everything.
build_all()
{
    build_llvm
    build_lib
    run_unit_tests
    build_python
}

# Function to build only the LLVM part of the library.
build_llvm()
{
    if $SKIP_LLVM_BUILD
    then
        echo "Skipping LLVM part of the library build"
    else
        echo "*******************************************************"
        echo "** Building LLVM, release tag: $LLVM_GIT_TAG"
        echo "*******************************************************"

        if $NO_CLEANUP
        then
            echo "Preserving temporary LLVM source and build files"
        fi

        # Cleanup from a previous bad or cancelled build
        rm -rf $LLVM_TEMP_DIR

        # Clone the LLVM source
        clone_llvm

        # Apply modifications to LLVM source
        cp -r src/llvm-project/llvm $LLVM_TEMP_DIR

        # Build LLVM
        cmake -DCMAKE_BUILD_TYPE=Release -B$LLVM_TEMP_DIR/build/release $LLVM_TEMP_DIR/llvm
        cmake --build $LLVM_TEMP_DIR/$BUILD_DIR --parallel $BUILD_JOBS

        echo "*******************************************************"
        echo "** Installing LLVM"
        echo "*******************************************************"

        # Install LLVM
        cmake --install $LLVM_TEMP_DIR/$BUILD_DIR --prefix $LLVM_LIB_DIR

        # Clean up, remove LLVM source and temporary build files
        if ! $NO_CLEANUP
        then
            rm -rf $LLVM_TEMP_DIR
        fi
    fi # $SKIP_LLVM_BUILD
}

# Function to build only the Arm Disassembly Library, examples, and tests.
# Requires LLVM to have already been built before hand, fails otherwise.
build_lib()
{
    # Check whether an LLVM build already exists.
    if [[ ! -s $LLVM_LIB_DIR ]]
    then
        echo "ERROR: $LLVM_LIB_DIR does not exist, cannot build the Arm Disassembly Library"
        exit 1
    fi

    echo "***************************************************************"
    echo "** Building the Arm Disassembly Library, examples, and tests"
    echo "***************************************************************"

    # Generate build files
    if $BUILD_DEBUG
    then
        cmake -DCMAKE_BUILD_TYPE=Debug -B$BUILD_DIR .
    else
        cmake -DCMAKE_BUILD_TYPE=Release -B$BUILD_DIR .
    fi

    # Run the build
    cmake --build $BUILD_DIR --parallel $BUILD_JOBS
}

# Function to run only the unit tests for the Arm Disassembly Library.
# Requires the library to have already been built before hand, fails otherwise.
run_unit_tests()
{
    # Check whether an Arm Disassembly library build already exists.
    if [[ ! -s $LIB_PATH ]]
    then
        echo "ERROR: $LIB_PATH does not exist, cannot run the unit tests"
        exit 1
    fi

    echo "***************************************************************"
    echo "** Running unit tests"
    echo "***************************************************************"
    ctest --test-dir $BUILD_DIR/test --output-on-failure
}

# Function to build only the Python package for the Arm Disassembly Library.
# Requires the library to have already been built before hand, fails otherwise.
build_python()
{
    echo "***************************************************************"
    echo "** Building Python package"
    echo "***************************************************************"

    # Copy the libarmdisasm library into the python package structure
    if [[ ! -s $LIB_PATH ]]
    then
        echo "ERROR: $LIB_PATH does not exist, cannot build the python package"
        exit 1
    else
        cp $LIB_PATH python/armdisasm/
    fi

    # Remove any old build artifacts from a previous Python package
    rm -rf python/armdisasm/build

    # Build the Python package as a wheel
    python3 -m build --wheel python/
    if [[ $? -ne 0 ]]
    then
        echo "ERROR: Failed to build python package as wheel, rc=$?"
    else
        echo "Python package can be installed using: 'python3 -m pip install python/dist/<name_of_wheel_file>'"
    fi
}

### Main entry point for build script ###

# Start timer
start=$(date +%s)

# Only short option names supported on command-line
while getopts "adhj:lnpst" opt; do
    case $opt in
        a | --lib)
            BUILD_ALL=false
            BUILD_LIB=true
            ;;
        d | --debug)
            BUILD_DEBUG=true
            ;;
        h | --help)
            usage
            exit 0
            ;;
        j | --jobs)
            BUILD_JOBS=$(calculate_build_jobs "$OPTARG")
            ;;
        l | --llvm)
            BUILD_ALL=false
            BUILD_LLVM=true
            NO_CLEANUP=true
            ;;
        n | --no-cleanup)
            NO_CLEANUP=true
            ;;
        p | --python)
            BUILD_ALL=false
            BUILD_PYTHON=true
            ;;
        s | --skip-llvm)
            SKIP_LLVM_BUILD=true
            ;;
        t | --tests)
            BUILD_ALL=false
            UNIT_TESTS=true
            ;;
        * )
            usage
            exit 1
            ;;
    esac
done

echo "Using ${BUILD_JOBS} (of a possible ${MAX_BUILD_JOBS}) workers for build tasks"

# Determine build directory
if $BUILD_DEBUG
then
    BUILD_DIR=build/debug
else
    BUILD_DIR=build/release
fi

# Determine expected full library path
LIB_PATH=$BUILD_DIR/src/$LIBARMDISASM

if $BUILD_ALL; then build_all; fi
if $BUILD_LLVM; then build_llvm; fi
if $BUILD_LIB; then build_lib; fi
if $BUILD_PYTHON; then build_python; fi
if $UNIT_TESTS; then run_unit_tests; fi

# Stop timer and calculate total time taken
stop=$(date +%s)
elapsed=$(bc -l <<< "$stop - $start")

echo "****************************************************************"
echo "** All operations completed successfully (took $elapsed seconds)"
echo "****************************************************************"
