/* Copyright (c) (2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CC_LOCK_H_
#define _CORECRYPTO_CC_LOCK_H_

#include <corecrypto/cc_priv.h>

typedef struct cc_lock_ctx cc_lock_ctx_t;
int cc_lock_init(cc_lock_ctx_t *ctx, const char *group_name);

#if defined(_WIN32)
#include <windows.h>
#endif

//==============================================================================
//
//          corecrypto support for multithreaded environments
//
// This part of corecrypto is OS dependent and it serves two purposes
// a) It allows multiple threads to use ccrng()
// b) If the process is forked, it reseeds the ccrng, so that parent and child
//    state differs and generate different random numbers
//==============================================================================

#if CC_LINUX && CC_KERNEL && CC_DARWIN && CORECRYPTO_SIMULATE_POSIX_ENVIRONMENT
#define CC_LOCK_IMPL_POSIX 0 // this is only to allow linux development on macOS. It is not useful in practice.
#define CC_LOCK_IMPL_USER 0
#define CC_LOCK_IMPL_WIN 0
#define CC_LOCK_IMPL_KERNEL 1
#define CC_LOCK_IMPL_SGX 0
#elif CC_DARWIN && !CC_KERNEL && !CC_USE_L4 &&                          \
    !CC_EFI && CC_INTERNAL_SDK // For Apple OSs (macOS, iOS, watchOS, tvOS), except kernel, L4 and EFI
#define CC_LOCK_IMPL_POSIX 0
#define CC_LOCK_IMPL_USER 1
#define CC_LOCK_IMPL_WIN 0
#define CC_LOCK_IMPL_KERNEL 0
#define CC_LOCK_IMPL_SGX 0
#elif CC_DARWIN && CC_KERNEL // For the Apple Kernel
#define CC_LOCK_IMPL_POSIX 0
#define CC_LOCK_IMPL_USER 0
#define CC_LOCK_IMPL_WIN 0
#define CC_LOCK_IMPL_KERNEL 1
#define CC_LOCK_IMPL_SGX 0
#elif defined(_WIN32) // for Windows
#define CC_LOCK_IMPL_POSIX 0
#define CC_LOCK_IMPL_USER 0
#define CC_LOCK_IMPL_WIN 1
#define CC_LOCK_IMPL_KERNEL 0
#define CC_LOCK_IMPL_SGX 0
#elif CC_SGX // for SGX Enclave
#define CC_LOCK_IMPL_POSIX 0
#define CC_LOCK_IMPL_USER 0
#define CC_LOCK_IMPL_WIN 0
#define CC_LOCK_IMPL_KERNEL 0
#define CC_LOCK_IMPL_SGX 1
#elif CC_LINUX || !CC_INTERNAL_SDK // for systems that support pthread, such as Linux
#define CC_LOCK_IMPL_POSIX 1
#define CC_LOCK_IMPL_USER 0
#define CC_LOCK_IMPL_WIN 0
#define CC_LOCK_IMPL_KERNEL 0
#define CC_LOCK_IMPL_SGX 0
#else
#error No multithread environment defined for cc_lock.
#endif

//------------------------------------------------------------------------------
// os/lock library, Apple userland
//------------------------------------------------------------------------------
#if CC_LOCK_IMPL_USER
#include <pthread.h>
#include <os/lock.h>

#define CC_LOCK_LOCK(lock_ctx) os_unfair_lock_lock(&(lock_ctx)->lock)
#define CC_LOCK_TRYLOCK(lock_ctx) os_unfair_lock_trylock(&(lock_ctx)->lock)
#define CC_LOCK_UNLOCK(lock_ctx) os_unfair_lock_unlock(&(lock_ctx)->lock)
#define CC_LOCK_ASSERT(lock_ctx) os_unfair_lock_assert_owner(&(lock_ctx)->lock)

struct cc_lock_ctx {
    os_unfair_lock lock;
};

//------------------------------------------------------------------------------
//          POSIX library, Linux
//------------------------------------------------------------------------------
#elif CC_LOCK_IMPL_POSIX
#include <pthread.h>

#define CC_LOCK_LOCK(lock_ctx) pthread_mutex_lock(&(lock_ctx)->mutex)
#define CC_LOCK_TRYLOCK(lock_ctx) pthread_mutex_trylock(&(lock_ctx)->mutex)
#define CC_LOCK_UNLOCK(lock_ctx) pthread_mutex_unlock(&(lock_ctx)->mutex)
#define CC_LOCK_ASSERT(lock_ctx)

struct cc_lock_ctx {
    pthread_mutex_t mutex;
};

//------------------------------------------------------------------------------
//          Kext, XNU
//------------------------------------------------------------------------------
#elif CC_LOCK_IMPL_KERNEL

#include <kern/locks.h>
#define CC_LOCK_LOCK(lock_ctx) lck_mtx_lock((lock_ctx)->mutex)
#define CC_LOCK_TRYLOCK(lock_ctx) lck_mtx_try_lock((lock_ctx)->mutex)
#define CC_LOCK_UNLOCK(lock_ctx) lck_mtx_unlock((lock_ctx)->mutex)
#define CC_LOCK_ASSERT(lock_ctx) lck_mtx_assert((lock_ctx)->mutex, LCK_MTX_ASSERT_OWNED);

struct cc_lock_ctx {
    lck_mtx_t *mutex;
    lck_grp_t *group;
};

//------------------------------------------------------------------------------
//          Windows
//------------------------------------------------------------------------------
#elif CC_LOCK_IMPL_WIN

#define CC_LOCK_LOCK(lock_ctx)                                          \
    if (WaitForSingleObject((lock_ctx)->hMutex, INFINITE) != WAIT_OBJECT_0) \
        return CCERR_INTERNAL;
#define CC_LOCK_UNLOCK(lock_ctx) ReleaseMutex((lock_ctx)->hMutex)
#define CC_LOCK_ASSERT(lock_ctx)

struct cc_lock_ctx {
    HANDLE hMutex;
};

//------------------------------------------------------------------------------
//          SGX
//------------------------------------------------------------------------------
#elif CC_LOCK_IMPL_SGX
// Avoid an OCALL in the middle of RNG routines: use spinlocks instead of mutexes.
#include <pthread.h>

#define CC_LOCK_LOCK(lock_ctx)          pthread_spin_lock(&(lock_ctx)->lock)
#define CC_LOCK_UNLOCK(lock_ctx)        pthread_spin_unlock(&(lock_ctx)->lock)
#define CC_LOCK_ASSERT(lock_ctx)

struct cc_lock_ctx {
    pthread_spinlock_t lock;
};

//------------------------------------------------------------------------------
//          default
//------------------------------------------------------------------------------
#else
#error "cc_lock is not implemented."
#endif /* CC_LOCK_IMPL_USER */

#endif /* _CORECRYPTO_CC_LOCK_H_ */
