/*
 * Copyright (c) 2000-2024 Apple Inc. All rights reserved.
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

#pragma once

// check that we're being compiled from the unit-tests makefile and that UT_MODULE was found
#if defined(UT_MODULE) && (UT_MODULE == -1)
#error "UT_MODULE not defined, did you forget to add a `#define UT_MODULE <module>` in your test?"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>
#include <stdbool.h>
#include <mach/boolean.h>

__BEGIN_DECLS

// This file defines some function from libc that are used by the mocks.
// The testers are built with -nostdlibinc so the system headers folders (from the SDK) are not available when
// compiling these files.
// Having system headers folders available for the includes search would create conflicts when XNU code includes
// headers like string.h, sys/types.h etc' (which need to come from XNU).
// This is why it's not possible do add headers like <stdlib.h> here.
// Furthermore, even if we could have included system headers like stdlib.h, Having that and XNU headers in the same
// translation unit would have created conflicts with XNU-defined types which have the same name but a different type
// from the system includes definition.
// For example, every type in mach/mach_types.h is typedef'd as mach_port_t in the system headers.

// from stdlib.h
extern void *calloc(size_t count, size_t size);
extern void *aligned_alloc(size_t alignment, size_t size);
extern void free(void *ptr);
extern void *malloc(size_t size);
extern void *realloc(void *ptr, size_t size);
extern size_t malloc_size(const void * __unsafe_indexable ptr);
extern int rand(void);
extern void srand(unsigned seed);
extern int rand_r(unsigned *seed);
extern uint32_t arc4random(void);
extern __attribute__((noreturn)) void exit(int status);
extern __attribute__((noreturn)) void abort(void);
extern char * getenv(const char *name);
extern int atoi(const char *str);
extern int atexit(void (*)(void));

// from sys/cdefs.h
#if __STDC_VERSION__ < 199901 // this also includes C++
#define __restrict
#else
#define __restrict      restrict
#endif

// from stdio.h
extern int vsnprintf(char * __restrict str, size_t size, const char * __restrict format, va_list ap) __printflike(3, 0);
extern int snprintf(char * __restrict str, size_t size, const char * __restrict format, ...) __printflike(3, 4);
extern int vasprintf(char ** __restrict str, const char * __restrict format, va_list ap) __printflike(2, 0);
extern int asprintf(char ** __restrict str, const char * __restrict format, ...) __printflike(2, 3);

// from string.h
extern void *memcpy(void *__restrict dst, const void *__restrict src, size_t n);
extern void *memset(void *b, int c, size_t len);
extern int strcmp(const char *s1, const char *s2);
extern char *strstr(const char *haystack, const char *needle);
extern char *strdup(const char *s1);
extern size_t strlen(const char *s);

// from unistd.h
extern size_t write(int fildes, const void *buf, size_t nbyte);
#define STDOUT_FILENO 1
#define S_IRWXU         0000700         /* [XSI] RWX mask for owner */
extern int close(int fildes);
extern int mkstemp(char *templ);
extern int unlink(const char *path);
extern int fchmod(int fildes, int mode);

// from pthread.h
#if defined(__LP64__)
#define __PTHREAD_SIZE__                8176
#define __PTHREAD_ATTR_SIZE__           56
#define __PTHREAD_MUTEX_SIZE__          56
#define __PTHREAD_MUTEXATTR_SIZE__      8
#define __PTHREAD_COND_SIZE__           40
#define __PTHREAD_CONDATTR_SIZE__       8
#else // !__LP64__
#define __PTHREAD_SIZE__                4088
#define __PTHREAD_ATTR_SIZE__           36
#define __PTHREAD_MUTEX_SIZE__          40
#define __PTHREAD_MUTEXATTR_SIZE__      8
#define __PTHREAD_COND_SIZE__           24
#define __PTHREAD_CONDATTR_SIZE__       4
#endif
#if defined(__arm__) || defined(__arm64__)
#define PTHREAD_STACK_MIN              16384
#else
#define PTHREAD_STACK_MIN              8192
#endif

struct _opaque_pthread_attr_t {
	long __sig;
	char __opaque[__PTHREAD_ATTR_SIZE__];
};
struct _opaque_pthread_t {
	long __sig;
	void *__cleanup_stack;
	char __opaque[__PTHREAD_SIZE__];
};
struct _opaque_pthread_mutex_t {
	long __sig;
	char __opaque[__PTHREAD_MUTEX_SIZE__];
};
struct _opaque_pthread_mutexattr_t {
	long __sig;
	char __opaque[__PTHREAD_MUTEXATTR_SIZE__];
};
struct _opaque_pthread_cond_t {
	long __sig;
	char __opaque[__PTHREAD_COND_SIZE__];
};
struct _opaque_pthread_condattr_t {
	long __sig;
	char __opaque[__PTHREAD_CONDATTR_SIZE__];
};
typedef struct _opaque_pthread_attr_t __darwin_pthread_attr_t;
typedef struct _opaque_pthread_t *__darwin_pthread_t;
typedef unsigned long __darwin_pthread_key_t;
typedef struct _opaque_pthread_mutex_t __darwin_pthread_mutex_t;
typedef struct _opaque_pthread_mutexattr_t __darwin_pthread_mutexattr_t;
typedef struct _opaque_pthread_cond_t __darwin_pthread_cond_t;
typedef struct _opaque_pthread_condattr_t __darwin_pthread_condattr_t;

typedef __darwin_pthread_t pthread_t;
typedef __darwin_pthread_attr_t pthread_attr_t;
typedef __darwin_pthread_key_t pthread_key_t;
typedef __darwin_pthread_mutex_t pthread_mutex_t;
typedef __darwin_pthread_mutexattr_t pthread_mutexattr_t;
typedef __darwin_pthread_cond_t pthread_cond_t;
typedef __darwin_pthread_condattr_t pthread_condattr_t;

extern pthread_t pthread_self(void);
extern int pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void *), void *arg);
extern int pthread_join(pthread_t thread, void **value_ptr);
extern int pthread_setspecific(pthread_key_t key, const void *value);
extern void *pthread_getspecific(pthread_key_t key);
extern int pthread_key_create(pthread_key_t *key, void (*destructor)(void *));
extern int pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attr);
extern int pthread_mutex_destroy(pthread_mutex_t *mutex);
extern int pthread_mutex_lock(pthread_mutex_t *mutex);
extern int pthread_mutex_trylock(pthread_mutex_t *mutex);
extern int pthread_mutex_unlock(pthread_mutex_t *mutex);
extern int pthread_mutexattr_init(pthread_mutexattr_t *attr);
extern int pthread_mutexattr_destroy(pthread_mutexattr_t *attr);
extern int pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type);
#define PTHREAD_MUTEX_RECURSIVE         2
extern int pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr);
extern int pthread_cond_wait(pthread_cond_t *, pthread_mutex_t *mutex);
extern int pthread_cond_signal(pthread_cond_t *cond);
extern int pthread_cond_broadcast(pthread_cond_t *cond);
extern int pthread_cond_destroy(pthread_cond_t *cond);
extern size_t pthread_get_stacksize_np(pthread_t);
extern void* pthread_get_stackaddr_np(pthread_t);

// errno.h
#define EBUSY           16

extern int * __error(void);
#define errno (*__error())

// sysctl.h
extern int sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen);

// from setjmp.h
#if defined(__x86_64__)
#  define _JBLEN ((9 * 2) + 3 + 16)
#elif defined(__i386__)
#  define _JBLEN (18)
#elif defined(__arm__) && !defined(__ARM_ARCH_7K__)
#  define _JBLEN                (10 + 16 + 2)
#elif defined(__arm64__) || defined(__ARM_ARCH_7K__)
#  define _JBLEN                ((14 + 8 + 2) * 2)
#else
#  error Undefined platform for setjmp
#endif

typedef int jmp_buf[_JBLEN];

extern int setjmp(jmp_buf);
extern void longjmp(jmp_buf, int) __attribute__((__noreturn__));

// from time.h
#include <sys/time.h>
extern time_t time(time_t *tloc);

// from dlfcn.h
#define RTLD_DEFAULT    ((void *) -2)
extern void *dlsym(void *handle, const char *symbol);

__END_DECLS
