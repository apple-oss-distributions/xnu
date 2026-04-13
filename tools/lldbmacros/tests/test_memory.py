##
# Copyright (c) 2025 Apple Inc. All rights reserved.
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

"""
Test cases for memory.py macros.

This module contains pytest-based tests for the memory LLDB macros,
demonstrating the pytest infrastructure for LLDB macro testing.
"""

import sys
import json
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'utils'))
from lldb_session import with_lldb_session

MEMORY_UNIT_TEST_EXE = "test_memory_macros"

class TestMemory:
    """Test cases for memory.py macros."""

    @with_lldb_session(MEMORY_UNIT_TEST_EXE, "test_showmap_summary_basic")
    def test_showmap_function(self, session):
        """Test showmap macro with JSON output and verify correctness at both checkpoints."""
        
        # Stop at checkpoint1 and verify initial map state
        session.run_until_checkpoint("checkpoint1")
        map_address = session.get_variable("map").value
        # Run the showmap macro with the kernel_map and JSON flag at checkpoint1
        result = session.exec(f"showmap {map_address} -JV")
        json_output_1 = json.loads(result)
        
        expected_fields = [
            "vm_map", "pmap", "vm_size", "entries", "resident_pages",
            "page_shift"
        ]
        for field in expected_fields:
            assert field in json_output_1, f"Missing field '{field}' in JSON output at checkpoint1"

        # Verify the -V option adds vm_map_tree information
        assert "vm_map_tree" in json_output_1, "Missing 'vm_map_tree' field from -V option in JSON output"
        
        # Verify the structure of the first row
        first_row = json_output_1["vm_map_tree"]["rows"][0]
        assert len(first_row["nodes"]) == 1, f"Expected exactly 1 node in tree, got {len(first_row['nodes'])}"
        
        # Verify node structure
        first_node = first_row["nodes"][0]
        assert first_node["count"] == len(first_node["entries"]), "count should match number of entries"
        assert first_node["count"] == 5, f"Expected 5 entries in tree (including padding), got {first_node['count']}"

        assert json_output_1["vm_size"] > 0, f"vm_size should be positive, got {json_output_1['vm_size']}"
        assert json_output_1["entries"] == 3, f"Expected 3 entries, got {json_output_1['entries']}"
        assert json_output_1["page_shift"] == 10, f"Expected page_shift 10 at checkpoint1, got {json_output_1['page_shift']}"

        # Verify addresses are non-zero
        assert json_output_1["vm_map"] != 0, "vm_map address should not be 0"
        assert json_output_1["pmap"] != 0, "pmap address should not be 0"
        
        print("Checkpoint1 verification passed")
        
        # Continue to checkpoint2 and verify changed map state
        session.run_until_checkpoint("checkpoint2")
        
        # Run the showmap macro again at checkpoint2
        result = session.exec(f"showmap {map_address} -JV")
        try:
            json_output_2 = json.loads(result)
        except json.JSONDecodeError as e:
            assert False, f"Failed to parse JSON output at checkpoint2: {e}\nOutput: {result}"
        
        # Verify all expected fields are still present
        for field in expected_fields:
            assert field in json_output_2, f"Missing field '{field}' in JSON output at checkpoint2"

        # Verify the -V option still provides vm_map_tree at checkpoint2
        assert "vm_map_tree" in json_output_2, "Missing 'vm_map_tree' field from -V option at checkpoint2"
        
        # Verify the structure of the first row
        first_row = json_output_2["vm_map_tree"]["rows"][0]
        assert len(first_row["nodes"]) == 1, f"Expected exactly 1 node in tree, got {len(first_row['nodes'])}"
        
        # Verify node structure
        first_node = first_row["nodes"][0]
        assert first_node["count"] == len(first_node["entries"]), "count should match number of entries"
        assert first_node["count"] == 5, f"Expected 5 entries in tree (including padding), got {first_node['count']}"

        assert json_output_2["vm_size"] > 0, f"vm_size should be positive, got {json_output_2['vm_size']}"
        assert json_output_2["entries"] == 3, f"Expected 3 entries, got {json_output_2['entries']}"
        
        # Verify addresses are still non-zero
        assert json_output_2["vm_map"] != 0, "vm_map address should not be 0"
        assert json_output_2["pmap"] != 0, "pmap address should not be 0"
        
        # Verify that page_shift has changed from 10 to 3
        assert json_output_2["page_shift"] == 3, f"Expected page_shift 3 at checkpoint2, got {json_output_2['page_shift']}"
        
        print("Checkpoint2 verification passed")
