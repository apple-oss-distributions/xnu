// Copyright (c) 2023 Apple Inc.  All rights reserved.

#include <stddef.h>
#include <stdint.h>
#include <assert.h>

#define __container_of(ptr, type, field) __extension__({ \
	        const __typeof__(((type *)nullptr)->field) *__ptr = (ptr); \
	        (type *)((uintptr_t)__ptr - offsetof(type, field)); \
	})
#define OS_NOINLINE __attribute__((__noinline__))

#include "../../../../osfmk/kern/macro_help.h"
#include "../../../../osfmk/kern/priority_queue.h"
#include "../../../../libkern/c++/priority_queue.cpp"
