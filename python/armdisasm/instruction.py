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
This module provides the Instruction class for the Arm Disassembly Library.
"""

from ctypes import cast, addressof, POINTER, c_ubyte, c_char_p
import armdisasm


class Instruction:
    """
    A class representing a decoded instruction object.
    """
    def __init__(self, lib):
        """
        Constructor method for a decoded instruction object.
        """
        self.lib = lib   # C library used to provide Python bindings for the Arm Disassembly Library API.
        self.inst = self.lib.arm_disasm_inst_create()   # A reference to the decoded instruction.
        if self.inst is None:
            raise armdisasm.InstCreateException

    def __del__(self):
        """
        Deletion method for a decoded instruction object. This ensures memory
        allocated by the underlying C API is freed automatically when this
        object has been finalized.
        """
        try:
            self.lib.arm_disasm_inst_dispose(self.inst)
        except Exception:
            pass

    def __str__(self):
        """
        Return a string representation of an Instruction for debug purposes.
        """
        return f"""
        Instruction:\n
        lib: {self.lib}
        inst: {self.inst}
        text_disasm: {self.get_text_disasm()}
        size: {self.get_size()}
        encoding: {self.get_encoding_32()}
        encoding (bytes): {self.get_encoding_bytes().hex()}
        opcode mnemonic: {self.get_opcode_mnemonic()}
        num operands: {self.get_num_operands()}
        num reg operands: {self.get_num_reg_operands()}
        num imm operands: {self.get_num_imm_operands()}
        num reg written: {self.get_num_reg_written()}
        reads mem: {self.get_reads_mem()}
        writes mem: {self.get_writes_mem()}
        """

    def clear(self):
        """
        Clear the contents of an instruction by zeroing it. This is required if
        re-using the same instruction object to decode another instruction.
        """
        self.lib.arm_disasm_inst_clear(self.inst)

    def get_text_disasm(self):
        """
        Get the text disassembly of an instruction.

        Returns a string containing the textual disassembly of the instruction.
        """
        # Convert from C char pointer to Python string
        text = c_char_p(self.lib.arm_disasm_inst_get_text_disasm(self.inst))
        return str(text.value.decode())   # pylint: disable=no-member

    def get_size(self):
        """
        Get the size of an instruction.

        Returns an integer containing the number of bytes in the encoding of
        the instruction.
        """
        return int(self.lib.arm_disasm_inst_get_size(self.inst))

    def get_encoding_32(self):
        """
        Get the encoding of a 32-bit instruction.

        Returns the instruction encoding as hex.
        """
        return hex(self.lib.arm_disasm_inst_get_encoding_32(self.inst))

    def get_encoding_bytes(self):
        """
        Get the encoding bytes of an instruction.

        Returns the instruction encoding as a byte array.
        """
        # Convert from uint8 pointer to Python byte array.
        encoding = (c_ubyte * armdisasm.MAX_INST_LEN)()
        encoding_p = cast(addressof(encoding), POINTER(c_ubyte))
        self.lib.arm_disasm_inst_get_encoding_bytes(self.inst, encoding_p)
        return bytearray(encoding)

    def get_opcode_mnemonic(self):
        """
        Get the mnemonic of an instruction's opcode.

        Returns a string containing the opcode mnemonic.
        """
        # Convert from C char pointer to Python string
        mnemonic = c_char_p(self.lib.arm_disasm_inst_get_opcode_mnemonic(self.inst))
        return str(mnemonic.value.decode())   # pylint: disable=no-member

    def get_num_operands(self):
        """
        Get the number of operands for an instruction.

        Returns an integer containing the total number of operands used by the
        instruction. This includes both explicit register operands and implicit
        immediates.
        """
        return int(self.lib.arm_disasm_inst_get_num_operands(self.inst))

    def get_num_reg_operands(self):
        """
        Get the number of register operands for an instruction.

        Returns an integer containing the number of register operands.
        """
        return int(self.lib.arm_disasm_inst_get_num_reg_operands(self.inst))

    def get_num_imm_operands(self):
        """
        Get the number of immediate operands for an instruction.

        Returns an integer containing the number of immediate operands.
        """
        return int(self.lib.arm_disasm_inst_get_num_imm_operands(self.inst))

    def get_num_reg_written(self):
        """
        Get the number of registers written for an instruction.

        Returns the number of registers written to by the instruction. This
        includes registers involved in base-register writeback, as well as the
        Arm condition flags {N, Z, C, V}.
        """
        return int(self.lib.arm_disasm_inst_get_num_reg_written(self.inst))

    def get_reads_mem(self):
        """
        Get whether or not an instruction could possibly load memory.

        Returns True if the instruction may load memory, False otherwise.
        """
        return bool(self.lib.arm_disasm_inst_get_reads_mem(self.inst))

    def get_writes_mem(self):
        """
        Get whether or not an instruction could possibly modify memory.

        Returns True if the instruction may modify memory, False otherwise.
        """
        return bool(self.lib.arm_disasm_inst_get_writes_mem(self.inst))
