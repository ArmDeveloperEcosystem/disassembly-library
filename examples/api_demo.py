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
This is an example program to demonstrate what we can do with the Arm
Disassembly Library API. This program takes a 4 byte instruction encoding
(provided on the CLI as a hex), disassembles the instruction to text, and
then exercises some of the available APIs from the library.

Usage of this API is as follows:
  1) Initialize disassembly components (once only)
  2) Create a Disassembler object
  3) Decode the instruction, using the Disassembler, to obtain an Instruction object
  4) Query information about the Instruction via the accessor methods provided
"""

import argparse
import sys

# Import the Arm Disassembly Library
import armdisasm


def str_to_hex(s):
    """
    Simple utility function to convert an input string to a base 16 numeric.
    """
    return int(s, 16)


if __name__ == "__main__":
    parser = argparse.ArgumentParser("Demonstrate what can be done with the Arm Disassembly Library from within a \
                                     Python program")
    parser.add_argument("-i", "--instruction", type=str_to_hex, required=True, help="(required) Instruction bit \
                        pattern to decode (specified as hex string e.g. 0xb8607b21)")
    opts = parser.parse_args()

    # Create an AArch64 disassembler using the loaded library.
    try:
        disasm = armdisasm.Disassembler(armdisasm.ArmDisasmArch.AARCH64)
    except armdisasm.DisasmCreateException as e:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)

    # Configure details of the output disassembly format.
    try:
        disasm.set_option(armdisasm.ArmDisasmOption.PRINT_IMM_HEX)
    except armdisasm.DisasmOptionException as e:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)

    # Decode the instruction bit pattern provided on the CLI.
    try:
        inst = disasm.decode_32(opts.instruction)
    except armdisasm.InstDecodeException as e:
        print(f"{e}", file=sys.stderr)
        sys.exit(1)

    # Print the text disassembly of the instruction.
    print(f"Text disassembly ({len(inst.get_text_disasm())} bytes): {inst.get_text_disasm()}")

    # Now find out some interesting things about the decoded instruction.
    print(f"Size of instruction: {inst.get_size()} bytes")
    print(f"Encoding: {inst.get_encoding_32()}")
    print(f"Encoding (bytes): [{inst.get_encoding_bytes().hex()}]")
    print(f"Opcode mnemonic: {inst.get_opcode_mnemonic()}")
    print(f"Number of operands: {inst.get_num_operands()}")
    print(f"  Register operands: {inst.get_num_reg_operands()}")
    print(f"  Immediate operands: {inst.get_num_imm_operands()}")
    print(f"Number of registers written: {inst.get_num_reg_written()}")
    print(f"Reads memory: {inst.get_reads_mem()}")
    print(f"Writes memory: {inst.get_writes_mem()}")

    # Take a hard-coded instruction and convert it into a byte array.
    inst_bytes = bytearray("0xb8607b21", "utf-8")

    # Decode it to get another decoded instruction.
    try:
        another_inst = disasm.decode_bytes(inst_bytes, armdisasm.AARCH64_INST_LEN)
    except armdisasm.InstDecodeException as e:
        print(f"{e}", file=sys.stderr)

    # Find out something interesting about the other instruction.
    print(f"Opcode mnemonic of another instruction: {another_inst.get_opcode_mnemonic()}")
    print(f"Size of another instruction: {another_inst.get_size()} bytes")

    # No need to dispose of anything, clean up is automatic.
