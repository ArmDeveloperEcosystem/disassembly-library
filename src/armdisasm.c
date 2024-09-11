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
* This is the public API for the Arm Disassembly Library.
*/
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "armdisasm.h"
#include <llvm-c/Disassembler.h>
#include <llvm-c/Target.h>

#define ARM_DISASM_OPTION_USE_MARKUP_VAL 1 // LLVMDisassembler_Option_UseMarkup
#define ARM_DISASM_OPTION_PRINT_IMM_HEX_VAL 2 // LLVMDisassembler_Option_PrintImmHex

/******************************************************************************
************************** Private internal functions *************************
******************************************************************************/

static inline char is_mnemonic_trim_char(char c)
{
    return c == ' ' || c == '{' || c == '[';
}

static void arm_disasm_trim_mnemonic(char *mnemonic)
{
    /* Mnemonics returned by LLVM sometimes contain trailing {, [, or spaces.
     * Trim these out. */
    int last_char_i = strlen(mnemonic) - 1;
    while(last_char_i >= 0 && is_mnemonic_trim_char(mnemonic[last_char_i]))
    {
        mnemonic[last_char_i--] = '\0';
    }
}

static void arm_disasm_init_aarch64(void)
{
    /* Initialisation of AArch64 components. */
    LLVMInitializeAArch64AsmPrinter();
    LLVMInitializeAArch64Target();
    LLVMInitializeAArch64TargetInfo();
    LLVMInitializeAArch64TargetMC();
    LLVMInitializeAArch64Disassembler();
}

static void arm_disasm_init_priv(void)
{
    arm_disasm_init_aarch64();
}

static arm_disasm_t arm_disasm_create_priv(const arm_disasm_arch_t arch)
{
    switch(arch)
    {
        case ARM_DISASM_ARCH_AARCH64:
            return LLVMCreateDisasmAllFeatures("aarch64-unknown-linux-gnu", NULL, 0, NULL, NULL);
            break;

        /* If adding support for new architectures, arm_disasm_init_priv() must
         * be updated to initialize the new components for that architecture. */

        default:
            return NULL;
            break;
    }
}

static arm_disasm_rc_t arm_disasm_set_option_priv(arm_disasm_t disasm, arm_disasm_option_t option)
{
    uint64_t set_option = ARM_DISASM_OPTION_INVALID;

    switch(option)
    {
        case ARM_DISASM_OPTION_USE_MARKUP:
            set_option |= (1 << ARM_DISASM_OPTION_USE_MARKUP_VAL);
            break;

        case ARM_DISASM_OPTION_PRINT_IMM_HEX:
            set_option |= (1 << ARM_DISASM_OPTION_PRINT_IMM_HEX_VAL);
            break;

        default:
            /* Unknown option. */
            return ARM_DISASM_RC_DISASM_OPTION_FAILURE;
            break;
    }

    if(LLVMSetDisasmOptions(disasm, set_option) != 1)
    {
        return ARM_DISASM_RC_DISASM_OPTION_FAILURE;
    }

    return ARM_DISASM_RC_SUCCESS;
}

static void arm_disasm_dispose_priv(arm_disasm_t disasm)
{
    LLVMDisasmDispose(disasm);
}

static arm_disasm_internal_inst_t *arm_disasm_internal_inst_create_priv(void)
{
    return LLVMMCInstCreate();
}

static void arm_disasm_internal_inst_dispose_priv(arm_disasm_internal_inst_t *inst)
{
    LLVMMCInstDispose(inst);
}

static size_t arm_disasm_inst_decode_bytes_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t *inst, uint8_t *input, uint64_t input_len, char *buffer, uint64_t buffer_len)
{
    /* Address is hard-coded to zero since it's not used for AArch64 decode. */
    return LLVMDecodeAndDisasmInstruction(disasm, inst, input, input_len, 0, buffer, buffer_len);
}

static void arm_disasm_inst_set_encoding_priv(arm_disasm_inst_t *inst, uint8_t *bytes)
{
    switch(inst->size)
    {
        case ARM_DISASM_AARCH64_INST_LEN:
            memcpy(&(inst->encoding.bits_32), bytes, ARM_DISASM_AARCH64_INST_LEN);
            break;

        default:
            /* Unrecognised encoding length. */
            break;
    }
}

static uint32_t arm_disasm_inst_get_size_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t inst)
{
    return LLVMMCInstGetSize(disasm, inst);
}

static const char *arm_disasm_inst_get_opcode_mnemonic_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t inst)
{
    return LLVMMCInstGetOpcodeMnemonic(disasm, inst);
}

static void arm_disasm_inst_set_mnemonic_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t *internal_inst, arm_disasm_inst_t *inst)
{
    strncpy(inst->mnemonic, arm_disasm_inst_get_opcode_mnemonic_priv(disasm, internal_inst), ARM_DISASM_MAX_MNEMONIC_LEN);
    arm_disasm_trim_mnemonic(inst->mnemonic);
}

static uint32_t arm_disasm_inst_get_num_operands_priv(arm_disasm_internal_inst_t inst)
{
    return LLVMMCInstGetNumOperands(inst);
}

static uint32_t arm_disasm_inst_get_num_reg_operands_priv(arm_disasm_internal_inst_t inst)
{
    return LLVMMCInstGetNumRegOperands(inst);
}

static uint32_t arm_disasm_inst_get_num_imm_operands_priv(arm_disasm_internal_inst_t inst)
{
    return LLVMMCInstGetNumImmOperands(inst);
}

static uint32_t arm_disasm_inst_get_num_reg_written_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t inst)
{
    return LLVMMCInstGetNumDefs(disasm, inst);
}

static bool arm_disasm_inst_get_reads_mem_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t inst)
{
    return (bool)LLVMMCInstMayLoad(disasm, inst);
}

static bool arm_disasm_inst_get_writes_mem_priv(arm_disasm_t disasm, arm_disasm_internal_inst_t inst)
{
    return (bool)LLVMMCInstMayStore(disasm, inst);
}

/******************************************************************************
************************** Public external functions **************************
******************************************************************************/

void arm_disasm_init(void)
{
    arm_disasm_init_priv();
}

arm_disasm_t arm_disasm_create(const arm_disasm_arch_t arch)
{
    return arm_disasm_create_priv(arch);
}

arm_disasm_rc_t arm_disasm_set_option(arm_disasm_t disasm, arm_disasm_option_t option)
{
    if(disasm == NULL)
    {
        return ARM_DISASM_RC_DISASM_OPTION_FAILURE;
    }

    return arm_disasm_set_option_priv(disasm, option);
}

void arm_disasm_dispose(arm_disasm_t disasm)
{
    arm_disasm_dispose_priv(disasm);
}

arm_disasm_inst_t *arm_disasm_inst_create(void)
{
    arm_disasm_inst_t* inst = (arm_disasm_inst_t*)calloc(1, sizeof(arm_disasm_inst_t));

    return inst;
}

void arm_disasm_inst_dispose(arm_disasm_inst_t *inst)
{
    free(inst);
}

void arm_disasm_inst_clear(arm_disasm_inst_t *inst)
{
    memset(inst, 0, sizeof(arm_disasm_inst_t));
}

arm_disasm_rc_t arm_disasm_inst_decode_32(arm_disasm_t disasm, arm_disasm_inst_t *inst, uint32_t input)
{
    /* Convert the hex input into an array of bytes using memcpy(). */
    uint8_t input_bytes[ARM_DISASM_AARCH64_INST_LEN];
    memcpy(input_bytes, &input, sizeof(input_bytes));

    return arm_disasm_inst_decode_bytes(disasm, inst, input_bytes, ARM_DISASM_AARCH64_INST_LEN);
}

arm_disasm_rc_t arm_disasm_inst_decode_bytes(arm_disasm_t disasm, arm_disasm_inst_t *inst, uint8_t *bytes, uint64_t bytes_len)
{
    /* In order to decode, we need to create an internal instruction. */
    arm_disasm_internal_inst_t *internal_inst = arm_disasm_internal_inst_create_priv();

    if(internal_inst == NULL)
    {
        return ARM_DISASM_RC_DECODE_INST_FAILURE;
    }

    /* Try to decode and disassemble the instruction to text in one fell swoop. */
    const size_t decode_size = arm_disasm_inst_decode_bytes_priv(disasm, internal_inst, bytes, bytes_len, inst->text_disasm, ARM_DISASM_MAX_TEXT_DISASM_LEN);

    /* A decode size of 0 indicates that we failed to decode the instruction. */
    if(decode_size == 0)
    {
        /* Don't forget to free the internal instruction before failing. */
        arm_disasm_internal_inst_dispose_priv(internal_inst);

        return ARM_DISASM_RC_DECODE_INST_FAILURE;
    }

    /* Now gather and populate all properties for this decoded instruction. */
    inst->size = arm_disasm_inst_get_size_priv(disasm, internal_inst);
    arm_disasm_inst_set_encoding_priv(inst, bytes);
    arm_disasm_inst_set_mnemonic_priv(disasm, internal_inst, inst);
    inst->num_operands = arm_disasm_inst_get_num_operands_priv(internal_inst);
    inst->num_reg_operands = arm_disasm_inst_get_num_reg_operands_priv(internal_inst);
    inst->num_imm_operands = arm_disasm_inst_get_num_imm_operands_priv(internal_inst);
    inst->num_reg_written = arm_disasm_inst_get_num_reg_written_priv(disasm, internal_inst);
    inst->reads_mem = arm_disasm_inst_get_reads_mem_priv(disasm, internal_inst);
    inst->writes_mem = arm_disasm_inst_get_writes_mem_priv(disasm, internal_inst);

    /* Dispose of the internal instruction, no longer needed. */
    arm_disasm_internal_inst_dispose_priv(internal_inst);

    return ARM_DISASM_RC_SUCCESS;
}

arm_disasm_rc_t arm_disasm_inst_print_text_disasm(const arm_disasm_inst_t *inst, char *buffer, uint64_t buffer_len)
{
    if((inst == NULL) || (buffer == NULL) || (buffer_len <= 0) || (buffer_len > ARM_DISASM_MAX_TEXT_DISASM_LEN))
    {
        return ARM_DISASM_RC_PRINT_DISASM_FAILURE;
    }

    /* Copy the text disassembly into the supplied buffer. */
    strncpy(buffer, inst->text_disasm, buffer_len);

    return ARM_DISASM_RC_SUCCESS;
}

const char *arm_disasm_inst_get_text_disasm(const arm_disasm_inst_t *inst)
{
    return inst->text_disasm;
}

uint32_t arm_disasm_inst_get_size(const arm_disasm_inst_t *inst)
{
    return inst->size;
}

void arm_disasm_inst_get_encoding_bytes(const arm_disasm_inst_t *inst, uint8_t *buffer)
{
    memcpy(buffer, inst->encoding.bytes, inst->size);
}

uint32_t arm_disasm_inst_get_encoding_32(const arm_disasm_inst_t *inst)
{
    return inst->encoding.bits_32;
}

const char *arm_disasm_inst_get_opcode_mnemonic(const arm_disasm_inst_t *inst)
{
    return inst->mnemonic;
}

uint32_t arm_disasm_inst_get_num_operands(const arm_disasm_inst_t *inst)
{
    return inst->num_operands;
}

uint32_t arm_disasm_inst_get_num_reg_operands(const arm_disasm_inst_t *inst)
{
    return inst->num_reg_operands;
}

uint32_t arm_disasm_inst_get_num_imm_operands(const arm_disasm_inst_t *inst)
{
    return inst->num_imm_operands;
}

uint32_t arm_disasm_inst_get_num_reg_written(const arm_disasm_inst_t *inst)
{
    return inst->num_reg_written;
}

bool arm_disasm_inst_get_reads_mem(const arm_disasm_inst_t *inst)
{
    return inst->reads_mem;
}

bool arm_disasm_inst_get_writes_mem(const arm_disasm_inst_t *inst)
{
    return inst->writes_mem;
}
