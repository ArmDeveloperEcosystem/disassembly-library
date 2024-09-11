/*
* SPDX-FileCopyrightText: Copyright (C) 2024 Arm Limited and/or its affiliates
* SPDX-FileCopyrightText: <open-source-office@arm.com>
* SPDX-License-Identifier: Apache-2.0
*
* Licensed under the Apache License, Version 2.0 (the "License"); you may not
* use this file except in compliance with the License. You may obtain a copy
* of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
* WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
* License for the specific language governing permissions and limitations
* under the License.
*
* This is an example program to demonstrate what we can do with the Arm
* Disassembly Library API. This program takes a 4 byte instruction encoding
* (provided on the CLI as a hex), disassembles the instruction to text, and
* then exercises some of the available APIs.
*
* Usage of this API is as follows:
*   1) Initialize disassembly components (once only)
*   2) Create a disassembler (once only)
*   3) Decode the instruction, using the disassembler, to obtain a handle
*   4) Query information about the instruction via the API provided
*   5) Dispose of the disassembler when no longer needed
*/

#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <armdisasm.h>

/*
 * Do some basic validation of the CLI arguments and extract the instruction.
 * No fancy arg parsing, just assume argv[1] contains a hex string for now.
 */
static uint32_t parse_cli_args(int argc, char *argv[])
{
    uint32_t cli_arg;

    /* Exactly one argument is supported (in addition to program name). */
    if(argc != 2)
    {
        printf("ERROR: Incorrect number of arguments specified.\n");
        exit(1);
    }

    /* Extract the instruction provided. Cater for lack of 0x prefix. */
    if(strncmp("0x", argv[1], 2) == 0)
    {
        cli_arg = strtol(argv[1], NULL, 0); // Prefixed with 0x, e.g. 0xf8408c20
    }
    else
    {
        cli_arg = strtol(argv[1], NULL, 16); // Not prefixed with 0x, e.g. f8408c20
    }

    /* Return the instruction encoding extracted from the input args. */
    return cli_arg;
}

/*
 * Main entry point into the demo application.
 */
int main(int argc, char *argv[])
{
    /* Return code that can be re-used throughout the program. */
    arm_disasm_rc_t rc = ARM_DISASM_RC_SUCCESS;

    /* Initialization of disassembly components. */
    arm_disasm_init();

    /* Create an AArch64 disassembler. */
    arm_disasm_t disasm = arm_disasm_create(ARM_DISASM_ARCH_AARCH64);
    if(disasm == NULL)
    {
        printf("ERROR: Failed to create the disassembler.\n");
        return ARM_DISASM_RC_CREATE_DISASM_FAILURE;
    }

    /* Configure details of the output disassembly format. */
    rc = arm_disasm_set_option(disasm, ARM_DISASM_OPTION_PRINT_IMM_HEX);
    if(rc != ARM_DISASM_RC_SUCCESS)
    {
        printf("ERROR: Failed to set the disassembler option.\n");
        return rc;
    }

    /* The instruction bit pattern to decode is provided on the CLI. */
    uint32_t encoding = parse_cli_args(argc, argv);

    /* Allocate an instruction on the heap. */
    arm_disasm_inst_t *inst = arm_disasm_inst_create();
    if(inst == NULL)
    {
        printf("ERROR: Failed to create the instruction.\n");
        return ARM_DISASM_RC_CREATE_INST_FAILURE;
    }

    /* Decode the instruction. */
    rc = arm_disasm_inst_decode_32(disasm, inst, encoding);
    if(rc != ARM_DISASM_RC_SUCCESS)
    {
        printf("ERROR: Failed to decode the instruction.\n");
        return rc;
    }

    /* Prepare text disassembly of the instruction in the desired format. */
    char text_disasm[ARM_DISASM_MAX_TEXT_DISASM_LEN+1];
    rc = arm_disasm_inst_print_text_disasm(inst, text_disasm, ARM_DISASM_MAX_TEXT_DISASM_LEN);
    if(rc != ARM_DISASM_RC_SUCCESS)
    {
        printf("ERROR: Failed to print text disassembly for the instruction.\n");
        return rc;
    }

    /* Print the text disassembly of the instruction. */
    printf("Text disassembly (%zu bytes): %s\n", strlen(text_disasm), text_disasm);

    /* Get the instruction encoding as bytes. */
    uint8_t encoding_bytes[ARM_DISASM_MAX_INST_LEN];
    arm_disasm_inst_get_encoding_bytes(inst, encoding_bytes);

    /* Now find out some interesting things about the decoded instruction. */
    printf("Size of instruction: %d bytes\n", arm_disasm_inst_get_size(inst));
    printf("Encoding: 0x%x\n", arm_disasm_inst_get_encoding_32(inst));
    printf("Encoding (bytes): [%x, %x, %x, %x]\n", encoding_bytes[0], encoding_bytes[1], encoding_bytes[2], encoding_bytes[3]);
    printf("Opcode mnemonic: %s\n", arm_disasm_inst_get_opcode_mnemonic(inst));
    printf("Number of operands: %d\n", arm_disasm_inst_get_num_operands(inst));
    printf("  Register operands: %d\n", arm_disasm_inst_get_num_reg_operands(inst));
    printf("  Immediate operands: %d\n", arm_disasm_inst_get_num_imm_operands(inst));
    printf("Number of registers written: %d\n", arm_disasm_inst_get_num_reg_written(inst));
    printf("Reads memory: %s\n", arm_disasm_inst_get_reads_mem(inst) ? "True" : "False");
    printf("Writes memory: %s\n", arm_disasm_inst_get_writes_mem(inst) ? "True" : "False");

    /* Dispose of the heap-allocated instruction. */
    arm_disasm_inst_dispose(inst);

    /* This time, allocate an instruction on the stack. */
    arm_disasm_inst_t another_inst;

    /* Hard-code an instruction encoding as bytes. */
    uint8_t another_inst_bytes[] = { 0x20, 0x04, 0x00, 0x11 };

    /* Decode the same instruction encoding again. */
    rc = arm_disasm_inst_decode_bytes(disasm, &another_inst, another_inst_bytes, ARM_DISASM_AARCH64_INST_LEN);
    if(rc != ARM_DISASM_RC_SUCCESS)
    {
        printf("ERROR: Failed to decode the other instruction.\n");
        return rc;
    }

    /* Clean up any disassemblers created. */
    arm_disasm_dispose(disasm);

    return 0;
}
