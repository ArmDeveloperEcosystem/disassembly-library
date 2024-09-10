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
This module provides a Python package for the Arm Disassembly Library.
"""

# Provide easy access to everything from armdisasm.py, as well as the
# Disassembler and Instruction classes.
from .armdisasm import *   # noqa: F403
from .disassembler import Disassembler   # pylint: disable=cyclic-import   # noqa: F401
from .instruction import Instruction   # pylint: disable=cyclic-import   # noqa: F401


# Initialize the Arm Disassembly Library once and stash in a global.
armdisasmlib = armdisasm.init()   # pylint: disable=undefined-variable   # noqa: F405
