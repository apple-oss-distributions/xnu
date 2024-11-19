##
# Copyright (c) 2023 Apple Inc. All rights reserved.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_START@
#
# This file contains Original Code and/or Modifications of Original Code
# as defined in and that are subject to the Apple Public Source License
# Version 2.0 (the 'License'). You may not use this file except in
# compliance with the License. The rights granted to you under the License
# may not be used to create, or enable the creation or redistribution of,
# unlawful or unlicensed copies of an Apple operating system, or to
# circumvent, violate, or enable the circumvention or violation of, any
# terms of an Apple operating system software license agreement.
#
# Please obtain a copy of the License at
# http://www.opensource.apple.com/apsl/ and read it before using this file.
#
# The Original Code and all software distributed under the License are
# distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
# EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
# INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
# Please see the License for the specific language governing rights and
# limitations under the License.
#
# @APPLE_OSREFERENCE_LICENSE_HEADER_END@
##

# pylint: disable=invalid-name

""" Unit test examples

    This is not a real test suite. It only demonstrates various approaches developers
    can use to write a test.
"""

import contextlib
import io
import unittest.mock
from lldbtest.testcase import LLDBTestCase
import lldb

from lldbmock.utils import lookup_type

# Import macro function to be tested.
from process import ShowTask, P_LHASTASK, TF_HASPROC


class TestExamples(LLDBTestCase):
    """ Unit test examples. """

    ROUNDED_UP_PROC_SIZE = 2048

    # Mock global variable value (accessed by the macro being)
    @unittest.mock.patch('xnu.kern.globals.proc_struct_size', ROUNDED_UP_PROC_SIZE)
    def test_function(self):
        """ This test shows how to run complex function against a mock. """

        self.reset_mocks()

        PROC_ADDR = 0xffffffff90909090
        TASK_ADDR = PROC_ADDR + self.ROUNDED_UP_PROC_SIZE
        PROC_RO_ADDR = 0xffffff0040404040

        # Create fake proc_t instance at 0xffffffff90909090
        proc = self.create_mock('proc', PROC_ADDR).fromDict({
            'p_pid': 12345,
            'p_lflag': P_LHASTASK,
            'p_comm': b'test-proc\0'
        })

        # Create task which is expected to be placed + sizeof(proc)
        task = self.create_mock('task', TASK_ADDR).fromDict({
            'effective_policy': {
                'tep_sup_active': 0,
                'tep_darwinbg': 0,
                'tep_lowpri_cpu': 1
            },
            't_flags': TF_HASPROC
        })

        # Created shared proc_ro reference from both task/proc
        self.create_mock('proc_ro', PROC_RO_ADDR)
        proc.p_proc_ro = PROC_RO_ADDR
        task.bsd_info_ro = PROC_RO_ADDR

        # Capture stdout and check expected output
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            ShowTask([f'{TASK_ADDR:#x}'])

        # Note: Not the best way of writing a unit test.
        expected = (
            'task                 vm_map               ipc_space            #acts flags'
            '    pid   process              io_policy  wq_state  command'
            f'                         \n{TASK_ADDR:#x}   0x0                  0x0    '
            f'                  0        12345   {PROC_ADDR:#x}           L  0  0  0'
            '   test-proc                       \n'
        )
        self.assertEqual(stdout.getvalue(), expected)

    def test_command(self):
        """ Test a simple LLDB command from user's CLI.

            Creates mock of a structure and prints out member by using LLDB
            expression.
        """

        self.reset_mocks()

        PROC_ADDR = 0xffffffff90909090

        self.create_mock('proc', PROC_ADDR).fromDict({
            'p_pid': 12345,
            'p_lflag': P_LHASTASK,
            'p_comm': b'unit-test-proc\0'
        })

        res = self.run_command(f'p/x ((proc_t){PROC_ADDR:#x})->p_comm')
        self.assertEqual(res.GetOutput(), '(command_t) "unit-test-proc"\n')
        self.assertTrue(res.Succeeded())

    @unittest.skipIf(LLDBTestCase.kernel().startswith('mach.release'),
                     "Not available in RELEASE embedded")
    def test_sbapi(self):
        """ Test SBAPI on top of a mocked target. """

        DOFHELP_ADDR = 0xffffffff11220000

        # Construct simple data structure mock.
        self.create_mock('struct dof_helper', DOFHELP_ADDR).fromDict({
            'dofhp_mod': b'mock-mod',
            'dofhp_addr': 0x1234,
            'dofhp_dof': 0x5678
        })

        # Construct SBValue on top of the mock.
        addr = self.target.ResolveLoadAddress(DOFHELP_ADDR)
        sbv = self.target.CreateValueFromAddress('test',
                            addr, lookup_type('dof_helper_t'))

        self.assertTrue(sbv.IsValid() and sbv.error.success)

        # Check that LLDB SBAPI returns correct values from mock.
        err = lldb.SBError()
        self.assertEqual(
            sbv.GetChildMemberWithName('dofhp_mod').GetData().GetString(err, 0),
            "mock-mod"
        )
        self.assertEqual(
            sbv.GetChildMemberWithName('dofhp_addr').GetValueAsUnsigned(),
            0x1234
        )
        self.assertEqual(
            sbv.GetChildMemberWithName('dofhp_dof').GetValueAsUnsigned(),
            0x5678
        )

    @unittest.skipIf(LLDBTestCase.arch() != 'arm64e', "Only on arm64e")
    def test_skip_arch(self):
        """ Example of architecture specific test. """

        self.assertEqual(self.target.triple.split('-', 1)[0], 'arm64e')

    @unittest.skipIf(LLDBTestCase.variant() != 'DEVELOPMENT', "DEVELOPMENT kernel only")
    def test_skip_development(self):
        """ Test that runs only on release kernel. """

        self.assertEqual(LLDBTestCase.variant(), "DEVELOPMENT")
