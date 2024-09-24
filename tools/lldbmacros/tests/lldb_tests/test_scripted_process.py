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

""" Tests that ScriptedProcess mock behaves as expected. """

import unittest.mock
import io

import lldb
from lldbtest.testcase import LLDBTestCase
from lldbmock.memorymock import RawMock
from lldbmock.utils import lookup_type


class ScriptedProcessTest(LLDBTestCase):
    """ Scripted process unit test. """

    def test_RawMock(self):
        """ Install simple raw memory mock into a target. """

        RAWMOCK_ADDR = 0xffffffff00000000

        mock = RawMock(100)
        mock.setData(b"lldb-process-mock\x00")
        self.add_mock(RAWMOCK_ADDR, mock)

        # Test is using LLDB command intentionaly.
        res = self.run_command(f'x/s {RAWMOCK_ADDR:#x}')

        self.assertTrue(res.Succeeded())
        self.assertEqual(
            res.GetOutput(),
            f'{RAWMOCK_ADDR:#x}: "lldb-process-mock"\n'
        )

    def test_RawMockIO(self):
        """ Populate simple raw memory mock from provided IO. """

        RAWMOCK_ADDR = 0xffffffff50000000

        mock = RawMock.fromBufferedIO(io.BytesIO(b"lldb-io-mock\x00"))
        self.add_mock(RAWMOCK_ADDR, mock)

        # Test is using LLDB command intentionaly.
        res = self.run_command(f'x/s {RAWMOCK_ADDR:#x}')

        self.assertTrue(res.Succeeded())
        self.assertEqual(
            res.GetOutput(),
            f'{RAWMOCK_ADDR:#x}: "lldb-io-mock"\n'
        )

    def test_DuplicateMock(self):
        """ Install same simple mock to two VA locations. """

        mock = RawMock(100)
        mock.setData(b"shared-mock\x00")
        self.add_mock(0xffffffff10000000, mock)
        self.add_mock(0xffffffff20000000, mock)

        # Test both locations
        for addr in ('0xffffffff10000000', '0xffffffff20000000'):
            res = self.run_command(f'x/s {addr}')

            self.assertTrue(res.Succeeded())
            self.assertEqual(
                res.GetOutput(),
                f'{addr}: "shared-mock"\n'
            )

    def test_MockConflict(self):
        """ Check that we can't add overlapping mocks. """

        mock = RawMock(16)
        self.add_mock(0x12345, mock)
        with self.assertRaises(ValueError):
            mock = RawMock(16)
            self.add_mock(0x12346, mock)

    def test_SimpleMock(self):
        """ Mock instance of a simple type. """

        UINT_ADDR = 0xffffffff11223344

        self.create_mock('uint32_t', UINT_ADDR).setData(0x1234)

        res = self.run_command(f'p/x *((uint32_t *){UINT_ADDR:#x})')

        self.assertTrue(res.Succeeded())
        self.assertEqual(res.GetOutput(), "(uint32_t) 0x00001234\n")

    @unittest.skipIf(LLDBTestCase.kernel().startswith('mach.release'),
                     "Not available in RELEASE embedded")
    def test_CompoundMock(self):
        """ Mock instance of simple structure. """

        DOFHELPER_ADDR = 0xffffffff11220000

        # Construct simple data structure mock.
        self.create_mock('struct dof_helper', DOFHELPER_ADDR).fromDict({
            'dofhp_mod': b'mock-mod',
            'dofhp_addr': 0x1234,
            'dofhp_dof': 0x5678
        })

        # Construct SBValue on top of the mock.
        addr = self.target.ResolveLoadAddress(DOFHELPER_ADDR)
        sbv = self.target.CreateValueFromAddress(
            'test', addr, lookup_type('dof_helper_t'))

        self.assertTrue(sbv.IsValid() and sbv.error.success)

        # Check that LLDB SBAPI returns correct values from mock.
        err = lldb.SBError()
        self.assertEqual(
            sbv.GetChildMemberWithName('dofhp_mod').GetData()
               .GetString(err, 0),
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

    @unittest.skipIf(LLDBTestCase.kernel().startswith('mach.release'),
                     "Not available in RELEASE embedded")
    def test_CompoundMock_UpdateProperty(self):
        """ Test that mock can deserilize properties from update. """

        mock = self.create_mock('struct dof_helper', 0xffffffff55555555)
        mock.setData(
            b'hello-mock' + b'\x00'*54 +
            0xfeedface.to_bytes(length=8, byteorder='little') +
            0xdeadbeef.to_bytes(length=8, byteorder='little'))

        # Test that mock has de-serialized correctly whole blob above.
        self.assertEqual(mock.dofhp_mod[:10], b'hello-mock')
        self.assertEqual(mock.dofhp_addr, 0xfeedface)
        self.assertEqual(mock.dofhp_dof, 0xdeadbeef)

    def test_UnionMock(self):
        """ Test that simple union/bitfield propagates property updates. """

        mock = self.create_mock('kds_ptr', 0xffffffff30000000)

        mock.buffer_index = 0b111111111111111111111  # 21-bits
        self.assertEqual(mock.raw, 0x001fffff)

        mock.buffer_index = 0
        mock.offset = 0b11111111111  # 11-bits
        self.assertEqual(mock.raw, 0xffe00000)

        mock.raw = 0xffdffffe
        self.assertEqual(mock.buffer_index, 0x001ffffe)
        self.assertEqual(mock.offset, 0x7fe)

    def test_MockArray(self):
        """ Test simple mock of char array. """

        STR_ADDR = 0xffffffff33004400
        PTR_ADDR = 0xffffffff44000000

        # Construct an array in memory.
        arrtype = lookup_type('char').GetArrayType(256)
        marray = self.create_mock(arrtype, STR_ADDR)
        marray.setData(b'Hello World\x00')

        # Create a pointer to the array
        ptrtype = lookup_type('char').GetPointerType()
        mstr = self.create_mock(ptrtype, PTR_ADDR)
        mstr.setData(STR_ADDR)

        # Let LLDB print it.
        addr = self.target.ResolveLoadAddress(PTR_ADDR)
        sbv = self.target.CreateValueFromAddress('str', addr, ptrtype)
        self.assertTrue(sbv.IsValid() and sbv.error.success)

        err = lldb.SBError()
        self.assertEqual(sbv.GetPointeeData(0, 256).GetString(err, 0),
                         'Hello World')

    def test_MockTypedArray(self):
        """ Test array of compound types. """

        ARRAY_ADDR = 0xffffffff44003300

        arrtype = lookup_type('proc').GetArrayType(10)
        self.create_mock(arrtype, ARRAY_ADDR).fromDict({
            '0': {
                'p_comm': b'bar-foo\x00'
            },
            '1': {
                'p_comm': b'foo-bar\x00'
            }
        })

        res = self.run_command(f'p/x ((proc_t){ARRAY_ADDR:#x})[1].p_comm')
        self.assertTrue(res.Succeeded())

        # Check that elements don't overlap somehow
        # (use SBValue to exercise LLDB's internals)
        addr = self.target.ResolveLoadAddress(ARRAY_ADDR)
        sbv = self.target.CreateValueFromAddress('proc_arr', addr, arrtype)
        self.assertTrue(sbv.IsValid() and sbv.error.success)

        err = lldb.SBError()
        self.assertEqual(
            sbv.GetChildAtIndex(0).GetChildMemberWithName('p_comm')
               .GetData().GetString(err, 0),
            'bar-foo'
        )
        self.assertEqual(
            sbv.GetChildAtIndex(1).GetChildMemberWithName('p_comm')
               .GetData().GetString(err, 0),
            'foo-bar'
        )

    def test_NoNewAttributes(self):
        """ Test that mock instances are properly frozen after creation. """

        mock = self.create_mock(lookup_type('uint32_t'))

        with self.assertRaises(TypeError):
            mock.foo = 5

    @unittest.skipIf(LLDBTestCase.kernel().startswith('mach.release'),
                     "Not available in RELEASE embedded")
    def test_NestedStruct(self):
        """ Test that nested mocks properly serialize. """

        PROVNAME_ADDR = 0xffffffff70707070
        DTHELPER_ADDR = 0xffffffff80808080

        # Setup mock with fake values.
        arrtype = lookup_type('char').GetArrayType(256)
        marray = self.create_mock(arrtype, PROVNAME_ADDR)
        marray.setData(b'test-prov\x00')

        sbtype = lookup_type('dtrace_helper_provdesc_t')
        mock = self.create_mock(sbtype, DTHELPER_ADDR)

        mock.dthpv_provname = PROVNAME_ADDR
        mock.dthpv_pattr.dtpa_mod.dtat_name = 0x5

        # Serializer should prevent overflowing a member's size.
        with self.assertRaises(OverflowError):
            mock.dthpv_pattr.dtpa_args.dtat_class = 0x7777

        mock.dthpv_pattr.dtpa_args.dtat_class = 0x77

        # Obtain SBValue and check modified members
        addr = self.target.ResolveLoadAddress(DTHELPER_ADDR)
        sbv = self.target.CreateValueFromAddress('test', addr, sbtype)
        self.assertTrue(sbv.IsValid() and sbv.error.success)

        err = lldb.SBError()
        self.assertEqual(
            sbv.GetChildMemberWithName('dthpv_provname')
               .GetPointeeData(0, 256).GetString(err, 0),
            'test-prov'
        )
        self.assertEqual(
            sbv.GetValueForExpressionPath('.dthpv_pattr.dtpa_mod.dtat_name')
               .GetValueAsUnsigned(),
            0x5
        )
        self.assertEqual(
            sbv.GetValueForExpressionPath('.dthpv_pattr.dtpa_args.dtat_class')
               .GetValueAsUnsigned(),
            0x77
        )

    @unittest.mock.patch('xnu.kern.globals.proc_struct_size', 2048)
    def test_ProxyMock(self):
        """ Test anonymous members forwarding. """

        PROC_ADDR = 0xffffffff90909090
        PROC_RO_ADDR = 0xffffff0040404040

        mock = self.create_mock('proc', PROC_ADDR)

        mock.p_list.le_next = 0x12345678
        mock.p_smr_node.smrn_next = 0x12345678
        mock.p_pid = 12345
        mock.p_argc = 0x5
        mock.p_textvp = 0xfeedface
        mock.p_lflag = 0x00000002

        mock.p_comm = b'foobar'  # Use forwarding property

        task = self.create_mock('task', PROC_ADDR + 2048)

        task.effective_policy.tep_sup_active = 0
        task.effective_policy.tep_darwinbg = 0
        task.effective_policy.tep_lowpri_cpu = 1
        task.t_flags = 0x00800000

        self.create_mock('proc_ro', PROC_RO_ADDR)

        mock.p_proc_ro = PROC_RO_ADDR
        task.bsd_info_ro = PROC_RO_ADDR

        # Populate and test mock.
        res = self.run_command(f'p/x ((proc_t){PROC_ADDR:#x})->p_comm')
        self.assertEqual(res.GetOutput(), '(command_t) "foobar"\n')
        self.assertTrue(res.Succeeded())

        # Modify mock and test again.
        mock.p_forkcopy.p_comm = b'barfoo'  # Sub-mock prop wins
        self.invalidate_cache()

        res = self.run_command(f'p/x ((proc_t){PROC_ADDR:#x})->p_comm')
        self.assertEqual(res.GetOutput(), '(command_t) "barfoo"\n')
        self.assertTrue(res.Succeeded())
