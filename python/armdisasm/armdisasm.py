#!/usr/bin/env python3
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

"""
This module provides Python bindings for the Arm Disassembly Library API.
To use the API, import the armdisasm package and call the relevant library
functions.
"""

from ctypes import POINTER, Structure, CDLL, c_uint32, c_uint64, c_ubyte, c_bool, c_char_p
from enum import Enum
import os


# Constants
AARCH64_INST_LEN = 4               # Length of an AArch64 instruction encoding in bytes.
MAX_INST_LEN = 4                   # The maximum length of an instruction in bytes.
LIBARMDISASM = "libarmdisasm.so"   # Name of the library's shared object file.


class ArmDisasmException(Exception):
    """
    A base class representing an Arm Disassembly Library Exception.
    """


class DisasmCreateException(ArmDisasmException):
    """
    An exception raised when an attempt to create a disassembler has failed.
    """
    def __init__(self, arch):
        self.arch = arch

    def __str__(self):
        return f"Failed to create the {self.arch} disassembler."


class DisasmOptionException(ArmDisasmException):
    """
    An exception raised when an attempt to set a disassembler option has failed.
    """
    def __init__(self, option):
        self.option = option

    def __str__(self):
        return f"Failed to set the disassembler option: {self.option}."


class InstCreateException(ArmDisasmException):
    """
    An exception raised when an attempt to create an instruction has failed.
    """
    def __str__(self):
        return "Failed to create the instruction."


class InstDecodeException(ArmDisasmException):
    """
    An exception raised when an attempt to decode an instruction has failed.
    """
    def __init__(self, encoding):
        self.encoding = encoding

    def __str__(self):
        return f"""
        Failed to decode the instruction with encoding {hex(self.encoding)}.
        """


class ArmDisasmArch(Enum):
    """
    An enumeration of supported architectures for disassembly. The maximum
    number of supported architectures is NUM. Required by ctypes.
    """
    AARCH64 = 0
    NUM = 1

    @classmethod
    def from_param(cls, obj):
        """
        Implement the from_param class method required by ctypes. It converts
        the object into a type that the foreign C function will understand.
        """
        return int(obj)


class ArmDisasmRc(Enum):
    """
    An enumeration of return codes for the Arm Disassembly Library. Required by
    ctypes.
    """
    SUCCESS = 0
    CREATE_DISASM_FAILURE = 1
    DISASM_OPTION_FAILURE = 2
    CREATE_INST_FAILURE = 3
    DECODE_INST_FAILURE = 4
    PRINT_DISASM_FAILURE = 5

    @classmethod
    def from_param(cls, obj):
        """
        Implement the from_param class method required by ctypes. It converts
        the object into a type that the foreign C function will understand.
        """
        return int(obj)


class ArmDisasmOption(Enum):
    """"
    An enumeration of disassembler options. Required by ctypes.
    """
    INVALID = 0
    USE_MARKUP = 1
    PRINT_IMM_HEX = 2

    @classmethod
    def from_param(cls, obj):
        """
        Implement the from_param class method required by ctypes. It converts
        the object into a type that the foreign C function will understand.
        """
        return int(obj)


class ArmDisasm(Structure):
    """
    An opaque reference to a disassembler. Required by ctypes.
    """


class ArmDisasmInst(Structure):
    """
    An opaque reference to a decoded instruction. Required by ctypes.
    """


def configure_lib():
    """
    Load the Arm Disassembly Library's shared C library, teach ctypes about all
    possible argument types and return types, and then return the library so
    that it can be used by other things to decode.
    """
    # Load the shared library (located in the installation directory of this python package).
    libname = os.path.join(os.path.dirname(__file__), LIBARMDISASM)
    lib = CDLL(libname)

    # Set argument types for library functions.
    lib.arm_disasm_create.argtypes = [ArmDisasmArch]
    lib.arm_disasm_set_option.argtypes = [POINTER(ArmDisasm), ArmDisasmOption]
    lib.arm_disasm_dispose.argtypes = [POINTER(ArmDisasm)]
    lib.arm_disasm_inst_clear.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_dispose.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_decode_32.argtypes = [POINTER(ArmDisasm), POINTER(ArmDisasmInst), c_uint32]
    lib.arm_disasm_inst_decode_bytes.argtypes = [POINTER(ArmDisasm), POINTER(ArmDisasmInst), POINTER(c_ubyte),
                                                 c_uint64]
    lib.arm_disasm_inst_get_text_disasm.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_size.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_encoding_32.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_encoding_bytes.argtypes = [POINTER(ArmDisasmInst), POINTER(c_ubyte)]
    lib.arm_disasm_inst_get_opcode_mnemonic.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_num_operands.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_num_reg_operands.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_num_imm_operands.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_num_reg_written.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_reads_mem.argtypes = [POINTER(ArmDisasmInst)]
    lib.arm_disasm_inst_get_writes_mem.argtypes = [POINTER(ArmDisasmInst)]

    # Set return types for library functions.
    lib.arm_disasm_create.restype = POINTER(ArmDisasm)
    lib.arm_disasm_set_option.restype = ArmDisasmRc
    lib.arm_disasm_inst_create.restype = POINTER(ArmDisasmInst)
    lib.arm_disasm_inst_decode_32.restype = ArmDisasmRc
    lib.arm_disasm_inst_decode_bytes.restype = ArmDisasmRc
    lib.arm_disasm_inst_get_text_disasm.restype = c_char_p
    lib.arm_disasm_inst_get_size.restype = c_uint32
    lib.arm_disasm_inst_get_encoding_32.restype = c_uint32
    lib.arm_disasm_inst_get_opcode_mnemonic.restype = c_char_p
    lib.arm_disasm_inst_get_num_operands.restype = c_uint32
    lib.arm_disasm_inst_get_num_reg_operands.restype = c_uint32
    lib.arm_disasm_inst_get_num_imm_operands.restype = c_uint32
    lib.arm_disasm_inst_get_num_reg_written.restype = c_uint32
    lib.arm_disasm_inst_get_reads_mem.restype = c_bool
    lib.arm_disasm_inst_get_writes_mem.restype = c_bool

    return lib


def init():
    """
    Initialization of underlying disassembly components. This one-off procedure
    must be done before creating any Disassembler or Instruction objects.
    """
    # Configure the shared library.
    lib = configure_lib()

    # Initialize the Arm Disassembly Library.
    lib.arm_disasm_init()

    return lib
