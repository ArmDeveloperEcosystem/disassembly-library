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
# A test script that exercises the C examples application.
#

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
APP_NAME="examples"
BUILD_DEBUG=false

usage()
{
    echo "A test script that exercises the C examples application for the Arm Disassembly Library"
    echo ""
    echo "-d (debug)          Run the examples in the debug build directory"
    echo "-h (help)           Display usage"
}

# Only short option names supported on command-line
while getopts "dh" opt; do
    case $opt in
        d | --debug)
            BUILD_DEBUG=true
            ;;
        h | --help)
            usage
            exit 0
            ;;
        * )
            usage
            exit 1
            ;;
    esac
done

# Determine build directory
if $BUILD_DEBUG
then
    BUILD_DIR=build/debug
else
    BUILD_DIR=build/release
fi

# Set the correct app path.
APP_PATH="$SCRIPT_DIR/../$BUILD_DIR/$APP_NAME"

# Check the api_demo program has been compiled.
if [[ ! -s $APP_PATH/$APP_NAME ]]
then
    echo "ERROR: compiled '$APP_NAME' program doesn't exist in the '$APP_PATH' directory."
    exit 1
fi

# Define an array of example instruction encodings to test.
instructions=(0xb8607b21 0xa9bf7bfd 0x4ee18400 0x8b020021 0x4ee08440 0x04e10000 0x25e20c00 0xf8408c20 0x1e650887)

# Run the examples through the api_demo program.
for ((i=0; i < ${#instructions[@]}; i++))
do
    echo -e "Running example $i (${instructions[$i]})\n"
    $APP_PATH/$APP_NAME ${instructions[$i]}
    echo ""
done

exit 0
