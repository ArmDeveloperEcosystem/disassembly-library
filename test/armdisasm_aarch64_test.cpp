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
* This is a simple test program to ensure that core components of the Arm
* Disassembly Library are working correctly.
*/

#include <gtest/gtest.h>
#include <armdisasm.h>

using namespace std::string_literals;

// Basic fixture to encapsulate disassembly context
class armdisasm : public testing::Test
{
    virtual void SetUp() override
    {
        arm_disasm_init();
        disasm = arm_disasm_create(ARM_DISASM_ARCH_AARCH64);
    }

    virtual void TearDown() override
    {
        arm_disasm_dispose(disasm);
    }

protected:
    arm_disasm_t disasm;
 };

/******************************************************************************
****************************** Disassembler Tests *****************************
******************************************************************************/

TEST_F(armdisasm, invalidArchitecture)
{
    EXPECT_EQ(arm_disasm_create(ARM_DISASM_ARCH_NUM), nullptr);
}

TEST_F(armdisasm, validArchitecture)
{
    EXPECT_NE(arm_disasm_create(ARM_DISASM_ARCH_AARCH64), nullptr);
}

TEST_F(armdisasm, setInvalidOption)
{
    arm_disasm_rc_t rc = arm_disasm_set_option(disasm, ARM_DISASM_OPTION_INVALID);
    EXPECT_EQ(rc, ARM_DISASM_RC_DISASM_OPTION_FAILURE);
}

TEST_F(armdisasm, setValidOption)
{
    arm_disasm_rc_t rc = arm_disasm_set_option(disasm, ARM_DISASM_OPTION_PRINT_IMM_HEX);
    EXPECT_EQ(rc, ARM_DISASM_RC_SUCCESS);
}

/******************************************************************************
****************************** Instruction Tests ******************************
******************************************************************************/

TEST_F(armdisasm, createInstSucceed)
{
    arm_disasm_inst_t *inst = arm_disasm_inst_create();
    EXPECT_NE(inst, nullptr);
    arm_disasm_inst_clear(inst);
    arm_disasm_inst_dispose(inst);
}

/******************************************************************************
**************************** Decode Interface Tests ***************************
******************************************************************************/

TEST_F(armdisasm, decode32StackFail)
{
    arm_disasm_inst_t decoded_inst;
    arm_disasm_rc_t rc = arm_disasm_inst_decode_32(disasm, &decoded_inst, 0xffffffff);
    EXPECT_EQ(rc, ARM_DISASM_RC_DECODE_INST_FAILURE);
}

TEST_F(armdisasm, decode32StackSucceed)
{
    arm_disasm_inst_t decoded_inst;
    arm_disasm_rc_t rc = arm_disasm_inst_decode_32(disasm, &decoded_inst, 0x0ddf58a3);
    EXPECT_EQ(rc, ARM_DISASM_RC_SUCCESS);
    EXPECT_EQ(decoded_inst.mnemonic, "ld1\t"s);
    EXPECT_EQ(decoded_inst.text_disasm, "\tld1\t{ v3.h }[3], [x5], #2"s);
    EXPECT_EQ(decoded_inst.reads_mem, true);
}

TEST_F(armdisasm, decode32HeapFail)
{
    arm_disasm_inst_t *decoded_inst = arm_disasm_inst_create();
    arm_disasm_rc_t rc = arm_disasm_inst_decode_32(disasm, decoded_inst, 0xffffffff);
    EXPECT_EQ(rc, ARM_DISASM_RC_DECODE_INST_FAILURE);
    arm_disasm_inst_dispose(decoded_inst);
}

TEST_F(armdisasm, decode32HeapSucceed)
{
    arm_disasm_inst_t *decoded_inst = arm_disasm_inst_create();
    arm_disasm_rc_t rc = arm_disasm_inst_decode_32(disasm, decoded_inst, 0x0ddf58a3);
    EXPECT_EQ(rc, ARM_DISASM_RC_SUCCESS);
    EXPECT_EQ(decoded_inst->mnemonic, "ld1\t"s);
    EXPECT_EQ(decoded_inst->text_disasm, "\tld1\t{ v3.h }[3], [x5], #2"s);
    EXPECT_EQ(decoded_inst->reads_mem, true);
    arm_disasm_inst_dispose(decoded_inst);
}

TEST_F(armdisasm, decodeBytesStackFail)
{
    arm_disasm_inst_t decoded_inst;
    uint8_t encoding_bytes[] = { 0xff, 0xff, 0xff, 0xff };
    arm_disasm_rc_t rc = arm_disasm_inst_decode_bytes(disasm, &decoded_inst, encoding_bytes, ARM_DISASM_AARCH64_INST_LEN);
    EXPECT_EQ(rc, ARM_DISASM_RC_DECODE_INST_FAILURE);
}

TEST_F(armdisasm, decodeBytesStackSucceed)
{
    arm_disasm_inst_t decoded_inst;
    uint8_t encoding_bytes[] = { 0xa3, 0x58, 0xdf, 0x0d };
    arm_disasm_rc_t rc = arm_disasm_inst_decode_bytes(disasm, &decoded_inst, encoding_bytes, ARM_DISASM_AARCH64_INST_LEN);
    EXPECT_EQ(rc, ARM_DISASM_RC_SUCCESS);
    EXPECT_EQ(decoded_inst.mnemonic, "ld1\t"s);
    EXPECT_EQ(decoded_inst.text_disasm, "\tld1\t{ v3.h }[3], [x5], #2"s);
    EXPECT_EQ(decoded_inst.reads_mem, true);
}

TEST_F(armdisasm, decodeBytesHeapFail)
{
    arm_disasm_inst_t *decoded_inst = arm_disasm_inst_create();
    uint8_t encoding_bytes[] = { 0xff, 0xff, 0xff, 0xff };
    arm_disasm_rc_t rc = arm_disasm_inst_decode_bytes(disasm, decoded_inst, encoding_bytes, ARM_DISASM_AARCH64_INST_LEN);
    EXPECT_EQ(rc, ARM_DISASM_RC_DECODE_INST_FAILURE);
    arm_disasm_inst_dispose(decoded_inst);
}

TEST_F(armdisasm, decodeBytesHeapSucceed)
{
    arm_disasm_inst_t *decoded_inst = arm_disasm_inst_create();
    uint8_t encoding_bytes[] = { 0xa3, 0x58, 0xdf, 0x0d };
    arm_disasm_rc_t rc = arm_disasm_inst_decode_bytes(disasm, decoded_inst, encoding_bytes, ARM_DISASM_AARCH64_INST_LEN);
    EXPECT_EQ(rc, ARM_DISASM_RC_SUCCESS);
    EXPECT_EQ(decoded_inst->mnemonic, "ld1\t"s);
    EXPECT_EQ(decoded_inst->text_disasm, "\tld1\t{ v3.h }[3], [x5], #2"s);
    EXPECT_EQ(decoded_inst->reads_mem, true);
    arm_disasm_inst_dispose(decoded_inst);
}

/******************************************************************************
*************************** General Interface Tests ***************************
******************************************************************************/

TEST_F(armdisasm, printTextDisasmFail)
{
    arm_disasm_rc_t rc = arm_disasm_inst_print_text_disasm(nullptr, nullptr, 0);
    EXPECT_EQ(rc, ARM_DISASM_RC_PRINT_DISASM_FAILURE);
}

TEST_F(armdisasm, printTextDisasmSucceed)
{
    arm_disasm_inst_t *decoded_inst = arm_disasm_inst_create();
    arm_disasm_inst_decode_32(disasm, decoded_inst, 0x0ddf58a3);
    char buffer[ARM_DISASM_MAX_TEXT_DISASM_LEN+1];
    arm_disasm_rc_t rc = arm_disasm_inst_print_text_disasm(decoded_inst, buffer, ARM_DISASM_MAX_TEXT_DISASM_LEN);
    EXPECT_EQ(rc, ARM_DISASM_RC_SUCCESS);
}
