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
*/

/**
 * @file armdisasm.h
 * @brief Public API for the Arm Disassembly Library.
 *
 * This is the public API for the Arm Disassembly Library. This header file
 * should be included in any application wanting to use the library.
 *
 * @author Arm Limited
 */

#ifndef ARM_DISASM_H
#define ARM_DISASM_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The maximum length of a text disassembly string.
 */
#define ARM_DISASM_MAX_TEXT_DISASM_LEN 1024

/**
 * The maximum length of an opcode mnemonic string.
 */
#define ARM_DISASM_MAX_MNEMONIC_LEN 32

/**
 * The length of an AArch64 instruction encoding in bytes.
 */
#define ARM_DISASM_AARCH64_INST_LEN 4

/**
 * The maximum length of an instruction in bytes.
 * Set to be the length of the largest instruction we currently support.
 */
#define ARM_DISASM_MAX_INST_LEN ARM_DISASM_AARCH64_INST_LEN

/**
 * Attribute to indicate the visibility of symbols in the shared library.
 * ARM_DISASM_VISIBILITY can be overriden by the user, but if it hasn't been
 * defined then we'll use default visibility.
 */
#ifndef ARM_DISASM_VISIBILITY
#define ARM_DISASM_VISIBILITY __attribute__((visibility("default")))
#endif

/**
 * An opaque reference to a disassembler.
 */
typedef void *arm_disasm_t;

/**
 * An opaque reference to an internal decoded instruction.
 */
typedef void *arm_disasm_internal_inst_t;

/**
 * An enumeration of supported architectures for disassembly. The maximum
 * number of supported architectures is ARM_DISASM_ARCH_NUM.
 */
typedef enum arm_disasm_arch_s
{
    ARM_DISASM_ARCH_AARCH64 = 0,
    ARM_DISASM_ARCH_NUM,
} arm_disasm_arch_t;

/**
 * An enumeration of return codes for the Arm Disassembly Library.
 */
typedef enum arm_disasm_rc_s
{
    ARM_DISASM_RC_SUCCESS = 0,
    ARM_DISASM_RC_CREATE_DISASM_FAILURE,
    ARM_DISASM_RC_DISASM_OPTION_FAILURE,
    ARM_DISASM_RC_CREATE_INST_FAILURE,
    ARM_DISASM_RC_DECODE_INST_FAILURE,
    ARM_DISASM_RC_PRINT_DISASM_FAILURE,
} arm_disasm_rc_t;

/**
 * An enumeration of disassembler options.
 */
typedef enum arm_disasm_option_s
{
    ARM_DISASM_OPTION_INVALID = 0,
    ARM_DISASM_OPTION_USE_MARKUP,
    ARM_DISASM_OPTION_PRINT_IMM_HEX,
} arm_disasm_option_t;

/**
 * A union representing an instruction encoding.
 */
typedef union arm_disasm_inst_encoding_s
{
    uint8_t bytes[ARM_DISASM_MAX_INST_LEN];
    uint32_t bits_32;
} arm_disasm_inst_encoding_t;

/**
 * A structure representing a decoded instruction and its properties.
 */
typedef struct arm_disasm_inst_s
{
    char text_disasm[ARM_DISASM_MAX_TEXT_DISASM_LEN+1]; /* Text disassembly of the instruction. */
    uint32_t size; /* Size of the instruction encoding in bytes. */
    arm_disasm_inst_encoding_t encoding; /* Encoding of the instruction. */
    char mnemonic[ARM_DISASM_MAX_MNEMONIC_LEN+1]; /* Mnemonic of the instruction opcode. */
    uint32_t num_operands; /* Number of operands. */
    uint32_t num_reg_operands; /* Number of register operands. */
    uint32_t num_imm_operands; /* Number of immediate operands. */
    uint32_t num_reg_written; /* Number of registers written to. */
    bool reads_mem; /* Whether or not the instruction could read from memory. */
    bool writes_mem; /* Whether or not the instruction could modify memory. */
} arm_disasm_inst_t;

/**
 * @brief Initialization of disassembly components.
 *
 * This one-off procedure must be done before creating any disassemblers or
 * decoding any instructions.
 *
 * @return void
 */
ARM_DISASM_VISIBILITY
void arm_disasm_init(void);

/**
 * @brief Create a disassembler.
 *
 * Create a disassembler that can be used to decode instructions of the
 * specified architecture. Must be disposed of using arm_disasm_dispose().
 *
 * @param arch The architecture of the disassembler.
 * @return A reference to the disassembler.
 */
ARM_DISASM_VISIBILITY
arm_disasm_t arm_disasm_create(const arm_disasm_arch_t arch);

/**
 * @brief Set a disassembler's display options.
 *
 * Set a disassembler's display options. Returns ARM_DISASM_RC_SUCCESS if
 * successfully set the option, or ARM_DISASM_RC_DISASM_OPTION_FAILURE
 * otherwise.
 *
 * @param disasm A reference to the disassembler to set options for.
 * @param options The desired display option for the disassembler.
 * @return A return code indicating whether the display options were set.
 */
ARM_DISASM_VISIBILITY
arm_disasm_rc_t arm_disasm_set_option(arm_disasm_t disasm, arm_disasm_option_t options);

/**
 * @brief Dispose of a disassembler.
 *
 * Dispose of a disassembler that is no longer required.
 *
 * @param disasm A reference to the disassembler to dispose of.
 * @return void
 */
ARM_DISASM_VISIBILITY
void arm_disasm_dispose(arm_disasm_t disasm);

/**
 * @brief Create a new instruction.
 *
 * Create a new instruction by allocating memory on the heap for it. Must be
 * disposed of using arm_disasm_inst_dispose() when no longer required.
 *
 * @return A reference to the new instruction.
 */
ARM_DISASM_VISIBILITY
arm_disasm_inst_t *arm_disasm_inst_create(void);

/**
 * @brief Zero the contents of a decoded instruction.
 *
 * Zero the contents of a decoded instruction so that it can be re-used in
 * another decode operation (if desired).
 *
 * @param disasm A reference to the instruction to clear.
 * @return void
 */
ARM_DISASM_VISIBILITY
void arm_disasm_inst_clear(arm_disasm_inst_t *inst);

/**
 * @brief Dispose of an instruction.
 *
 * Dispose of an instruction that is no longer required. Only required for
 * instructions created using arm_disasm_inst_create().
 *
 * @param inst A reference to the instruction to dispose of.
 * @return void
 */
ARM_DISASM_VISIBILITY
void arm_disasm_inst_dispose(arm_disasm_inst_t *inst);

/**
 * @brief Decode a single instruction provided as a uint32_t.
 *
 * Decode a single instruction using the disassembler specified in the disasm
 * parameter. The instruction encoding is specified as a uint32_t in the bytes
 * parameter. If a valid instruction can be disassembled, its string is
 * returned indirectly and stored in the supplied inst structure. This function
 * returns SUCCESS if the instruction was decoded successfully, or a specific
 * DECODE_FAILURE return code otherwise.
 *
 * @param disasm A reference to the disassembler to use for decoding.
 * @param inst A reference to the structure the instruction is decoded into.
 * @param bytes The bytes of the instruction encoding to decode.
 * @return A return code indicating whether or not the decode was successful.
 */
ARM_DISASM_VISIBILITY
arm_disasm_rc_t arm_disasm_inst_decode_32(arm_disasm_t disasm, arm_disasm_inst_t *inst, uint32_t bytes);

/**
 * @brief Decode a single instruction provided as a sequence of uint8_t bytes.
 *
 * Decode a single instruction using the disassembler specified in the disasm
 * parameter. The instruction encoding is specified as a sequence of uint8_t
 * bytes in the bytes parameter. If a valid instruction can be disassembled,
 * its string is returned indirectly and stored in the supplied inst structure.
 * Returns ARM_DISASM_RC_SUCCESS if the instruction was decoded successfully,
 * or ARM_DISASM_RC_DECODE_FAILURE otherwise.
 *
 * @param disasm A reference to the disassembler to use for decoding.
 * @param inst A reference to the structure the instruction is decoded into.
 * @param bytes The input bytes of the instruction encoding to decode.
 * @param bytes_len The length of the bytes parameter, i.e. number of bytes.
 * @return A return code indicating whether or not the decode was successful.
 */
ARM_DISASM_VISIBILITY
arm_disasm_rc_t arm_disasm_inst_decode_bytes(arm_disasm_t disasm, arm_disasm_inst_t *inst, uint8_t *bytes, uint64_t bytes_len);

/**
 * @brief Print the text disassembly of a decoded instruction.
 *
 * Print the text disassembly of a decoded instruction to the supplied buffer.
 *
 * @param inst A reference to the decoded instruction to format.
 * @param buffer The output buffer to write the text disassembly to.
 * @param buffer_len The length of the output buffer in bytes.
 * @return A return code indicating whether or not the print was successful.
 */
ARM_DISASM_VISIBILITY
arm_disasm_rc_t arm_disasm_inst_print_text_disasm(const arm_disasm_inst_t *inst, char *buffer, uint64_t buffer_len);

/**
 * @brief Get the text disassembly of an instruction.
 *
 * @param inst A reference to the decoded instruction.
 * @return A null-terminated string containing the text disassembly.
 */
ARM_DISASM_VISIBILITY
const char *arm_disasm_inst_get_text_disasm(const arm_disasm_inst_t *inst);

/**
 * @brief Get the size of an instruction.
 *
 * Returns the number of bytes in the encoding of the instruction.
 *
 * @param inst A reference to the decoded instruction.
 * @return A uint32_t containing the size.
 */
ARM_DISASM_VISIBILITY
uint32_t arm_disasm_inst_get_size(const arm_disasm_inst_t *inst);

/**
 * @brief Get the byte encoding of an instruction.
 *
 * Copy the original encoding of the instruction into the supplied buffer.
 *
 * @param inst A reference to the decoded instruction.
 * @param buffer The output buffer to write the encoding to.
 * @return void
 */
ARM_DISASM_VISIBILITY
void arm_disasm_inst_get_encoding_bytes(const arm_disasm_inst_t *inst, uint8_t *buffer);

/**
 * @brief Get the uint32 encoding of an instruction.
 *
 * Return the original encoding of the instruction in bytes.
 *
 * @param inst A reference to the decoded instruction.
 * @return A uint32_t containing the instruction encoding bytes.
 */
ARM_DISASM_VISIBILITY
uint32_t arm_disasm_inst_get_encoding_32(const arm_disasm_inst_t *inst);

/**
 * @brief Get the mnemonic of an instruction opcode.
 *
 * Returns the mnemonic of the instruction opcode.
 *
 * @param inst A reference to the decoded instruction.
 * @return A null-terminated string containing the mnemonic.
 */
ARM_DISASM_VISIBILITY
const char *arm_disasm_inst_get_opcode_mnemonic(const arm_disasm_inst_t *inst);

/**
 * @brief Get the number of operands for an instruction.
 *
 * Returns the total number of operands used by the instruction. This includes
 * both explicit register operands and implicit immediates
 *
 * @param inst A reference to the decoded instruction.
 * @return A uint32_t containing the number of operands.
 */
ARM_DISASM_VISIBILITY
uint32_t arm_disasm_inst_get_num_operands(const arm_disasm_inst_t *inst);

/**
 * @brief Get the number of register operands for an instruction.
 *
 * @param inst A reference to the decoded instruction.
 * @return A uint32_t containing the number of register operands.
 */
ARM_DISASM_VISIBILITY
uint32_t arm_disasm_inst_get_num_reg_operands(const arm_disasm_inst_t *inst);

/**
 * @brief Get the number of immediate operands for an instruction.
 *
 * @param inst A reference to the decoded instruction.
 * @return A uint32_t containing the number of immediate operands.
 */
ARM_DISASM_VISIBILITY
uint32_t arm_disasm_inst_get_num_imm_operands(const arm_disasm_inst_t *inst);

/**
 * @brief Get the number of registers written for an instruction.
 *
 * Returns the number of registers written to by the instruction. This includes
 * registers involved in base-register writeback, as well as the Arm condition
 * flags {N, Z, C, V}.
 *
 * @param inst A reference to the decoded instruction.
 * @return A uint32_t containing the number of register definitions.
 */
ARM_DISASM_VISIBILITY
uint32_t arm_disasm_inst_get_num_reg_written(const arm_disasm_inst_t *inst);

/**
 * @brief Get whether or not an instruction could possibly load memory.
 *
 * @param inst A reference to the decoded instruction.
 * @return TRUE if the instruction may load memory, FALSE otherwise.
 */
ARM_DISASM_VISIBILITY
bool arm_disasm_inst_get_reads_mem(const arm_disasm_inst_t *inst);

/**
 * @brief Get whether or not an instruction could possibly modify memory.
 *
 * @param inst A reference to the decoded instruction.
 * @return TRUE if the instruction may modify memory, FALSE otherwise.
 */
ARM_DISASM_VISIBILITY
bool arm_disasm_inst_get_writes_mem(const arm_disasm_inst_t *inst);

#ifdef __cplusplus
}
#endif

#endif /* ARM_DISASM_H */
