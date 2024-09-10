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

#include <stdio.h>

/*
 * Main entry point into the demo application.
 */
int main(int argc, char *argv[])
{
    printf("TODO: this demo application needs to be written!");

    return 0;
}
