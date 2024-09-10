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
This module provides the Disassembler class for the Arm Disassembly Library.
"""

from ctypes import cast, addressof, POINTER, c_ubyte
import armdisasm


class Disassembler:
    """
    A class representing a disassembler object that can be used to decode and
    disassemble instructions.
    """
    def __init__(self, arch):
        """
        Constructor method for a disassembler object. When creating a
        disassembler, the target architecture must be specified. Internally, a
        reference to a disassembly context is automatically created and used in
        calls to the underlying C API.
        """
        self.lib = armdisasm.armdisasmlib   # C library providing Python bindings for the Arm Disassembly Library.
        self.arch = arch.value   # Specified architecture for the disassembler.
        self.disasm = self.lib.arm_disasm_create(self.arch)   # A reference to the disassembler context.
        if self.disasm is None:
            raise armdisasm.DisasmCreateException(self.arch)

    def __del__(self):
        """
        Deletion method for a disassembler object. This ensures memory
        allocated by the underlying C API is freed automatically when this
        object has been finalized.
        """
        try:
            self.lib.arm_disasm_dispose(self.disasm)
        except Exception:
            pass

    def __str__(self):
        """
        Return a string representation of a Disassembler for debug purposes.
        """
        return f"""
        Disassembler:\n
        lib: {self.lib}
        arch: {self.arch}
        disasm: {self.disasm}
        """

    def set_option(self, option):
        """
        Set the disassembler's display options. The possible display options
        are: USE_MARKUP, PRINT_IMM_HEX, ASM_VARIANT, and SET_INST_COMMENTS.
        Multiple options can be set, but only one at a time.
        """
        rc = self.lib.arm_disasm_set_option(self.disasm, option.value)
        if rc is not armdisasm.ArmDisasmRc.SUCCESS:
            raise armdisasm.DisasmOptionException(option.value)

    def decode_bytes(self, encoding_bytes, num_bytes):
        """
        Decode an instruction encoding provided as a byte array of length
        num_bytes. The encoding must be provided in little-endian.
        """
        inst = armdisasm.Instruction(self.lib)

        # Convert from byte array to uint8 pointer.
        encoding = (c_ubyte * len(encoding_bytes)).from_buffer(encoding_bytes)
        encoding_p = cast(addressof(encoding), POINTER(c_ubyte))
        rc = self.lib.arm_disasm_inst_decode_bytes(self.disasm, inst.inst, encoding_p, num_bytes)

        if rc is not armdisasm.ArmDisasmRc.SUCCESS:
            raise armdisasm.InstDecodeException(encoding)
        return inst

    def decode_32(self, encoding):
        """
        Decode a 32-bit instruction encoding provided as an integer.
        """
        inst = armdisasm.Instruction(self.lib)
        rc = self.lib.arm_disasm_inst_decode_32(self.disasm, inst.inst, encoding)
        if rc is not armdisasm.ArmDisasmRc.SUCCESS:
            raise armdisasm.InstDecodeException(encoding)
        return inst
