// Copyright (c) 2020 Apple Computer, Inc. All rights reserved.

#include <stdlib.h>
#include <os/atomic_private.h>

#define kheap_alloc(h, s, f) calloc(1, s)
#define kfree(p, s) free(p)
#define kalloc_type(t, f) calloc(1, sizeof(t))
#define kfree_type(t, p) free(p)
#define kalloc_data(s, f) calloc(1, s)
#define kfree_data(p, s) free(p)
#define panic(...) T_ASSERT_FAIL(__VA_ARGS__)
#define PE_i_can_has_debugger(...) true
#define SECURITY_READ_ONLY_LATE(X) X
#define __startup_func

#define ml_get_cpu_count() 6
