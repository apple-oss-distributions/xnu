/*
 * Copyright (c) 2023 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#if DEVELOPMENT || DEBUG

#include <kern/startup.h>
#include <kern/zalloc.h>
#include <sys/proc_ro.h>
#include <sys/vm.h>

#include <tests/ktest.h>

#include <libkern/tree.h>

/*
 * RB tree node that we use for testing.
 * The nodes are compared using the numeric `rbt_id'.
 */
struct rbt_test_node {
	RB_ENTRY(rbt_test_node) link;
	unsigned int rbt_id; /* comparison id */
	unsigned int rbt_flags;
#define RBT_FLAG_IN_USE 1
#define RBT_MASK_IN_USE 1
};

typedef struct rbt_test_node * __single rbt_test_node_t;

/*
 * Comparison function for rbt test nodes.
 */
static int
rbt_cmp(struct rbt_test_node *a, struct rbt_test_node *b)
{
	if (!a && !b) {
		return 0;
	} else if (a && !b) {
		return -1;
	} else if (!a && b) {
		return 1;
	} else if (a->rbt_id == b->rbt_id) {
		return 0;
	} else if (a->rbt_id < b->rbt_id) {
		return -1;
	} else {
		return 1;
	}
}

/*
 * Define a red-black tree type we are going to test.
 */
RB_HEAD(_rb_test_tree, rbt_test_node);
RB_PROTOTYPE(_rb_test_tree, rbt_test_node, link, rbt_cmp)
RB_GENERATE(_rb_test_tree, rbt_test_node, link, rbt_cmp)

/*
 * Array of test nodes that we are going to use.
 */
#define RBT_TEST_NODE_COUNT 7
static struct rbt_test_node test_nodes[RBT_TEST_NODE_COUNT];
static int test_node_ids[RBT_TEST_NODE_COUNT] = {88, 66, 44, 22, 0, 77, 55 };


static size_t
rb_tree_insert_nodes(struct _rb_test_tree *tree, size_t count)
{
	unsigned int idx = 0;
	if (RBT_TEST_NODE_COUNT < count) {
		count = RBT_TEST_NODE_COUNT;
	}

	for (idx = 0; idx < count; idx++) {
		rbt_test_node_t node = &test_nodes[idx];
		T_EXPECT_EQ_INT(node->rbt_flags & RBT_MASK_IN_USE, 0, "Trying to insert a tree node that is already in use");
		node->rbt_id = test_node_ids[idx];
		RB_INSERT(_rb_test_tree, tree, node);
		node->rbt_flags |= RBT_FLAG_IN_USE;
	}
	return count;
}

static size_t
rb_tree_remove_nodes(struct _rb_test_tree *tree, size_t count)
{
	unsigned int idx = 0;
	if (RBT_TEST_NODE_COUNT < count) {
		count = RBT_TEST_NODE_COUNT;
	}

	for (idx = 0; idx < count; idx++) {
		rbt_test_node_t node = &test_nodes[idx];
		T_EXPECT_EQ_INT(node->rbt_flags & RBT_MASK_IN_USE, 1, "Trying to remove a tree node that is not in use");
		T_EXPECT_EQ_INT(node->rbt_id, test_node_ids[idx], "The node id does not match the node index");
		RB_REMOVE(_rb_test_tree, tree, node);
		node->rbt_flags &= ~RBT_FLAG_IN_USE;
	}
	return count;
}

static int
rb_tree_test_run(__unused int64_t in, int64_t *out)
{
	struct _rb_test_tree test_tree;
	RB_INIT(&test_tree);

	rb_tree_insert_nodes(&test_tree, 7);
	rb_tree_remove_nodes(&test_tree, 7);

	*out = 0;
	return 0;
}

SYSCTL_TEST_REGISTER(rb_tree_test, rb_tree_test_run);

#endif /* DEVELOPMENT || DEBUG */
