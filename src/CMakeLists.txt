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

cmake_minimum_required(VERSION 3.20)

project(armdisasm)

## Find LLVM which is a dependency of armdisasm
set(CMAKE_PREFIX_PATH "../llvmlib")
find_package(LLVM REQUIRED CONFIG)

message(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
message(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

separate_arguments(LLVM_DEFINITIONS_LIST NATIVE_COMMAND ${LLVM_DEFINITIONS})

# Defines the LLVM components we want to reference in armdisasm. To support further targets, extend this list.
llvm_map_components_to_libnames(llvm_libs aarch64disassembler aarch64codegen)

# Build the shared library which contains the disassembly bindings and links LLVM
add_library(armdisasm SHARED armdisasm.c)
target_compile_definitions(armdisasm PRIVATE ${LLVM_DEFINITIONS_LIST})
target_include_directories(armdisasm PRIVATE ${LLVM_INCLUDE_DIRS} PUBLIC ../include)
target_link_libraries(armdisasm PRIVATE ${llvm_libs})
target_compile_options(armdisasm PRIVATE -fvisibility=hidden)

target_compile_options(armdisasm PRIVATE  -Wall -Wextra -Wpedantic -Werror)
