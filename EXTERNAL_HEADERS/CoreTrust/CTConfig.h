//
//  CTConfig.h
//  CoreTrust
//
//  Copyright © 2021 Apple. All rights reserved.
//

#ifndef _CORETRUST_CONFIG_H_
#define _CORETRUST_CONFIG_H_

#if EFI
// This requires $(SDKROOT)/usr/local/efi/include/Platform to be in your header
// search path.
#include <Apple/Common/Library/Include/EfiCompatibility.h>
#else // !EFI
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#endif // !EFI

/* Bounds attributes */
#if __has_include(<ptrcheck.h>)
#include <ptrcheck.h>
#else
#define __single
#define __unsafe_indexable
#define __counted_by(N)
#define __sized_by(N)
#define __ended_by(E)
#define __ptrcheck_abi_assume_single()
#define __ptrcheck_abi_assume_unsafe_indexable()
#define __unsafe_forge_bidi_indexable(T, P, S) ((T)(P))
#define __unsafe_forge_single(T, P) ((T)(P))
#endif

#if EFI
    #if defined(__cplusplus)
        #define __BEGIN_DECLS extern "C" {
        #define __END_DECLS }
    #else
        #define __BEGIN_DECLS
        #define __END_DECLS
    #endif
#else // !EFI
#include <sys/cdefs.h>
#endif // !EFI

__BEGIN_DECLS

#if EFI
typedef UINT8 CT_uint8_t;
typedef UINT32 CT_uint32_t;
typedef INT32 CT_int;
typedef UINT64 CT_uint64_t;
typedef size_t CT_size_t;
typedef BOOLEAN CT_bool;
#else // !EFI
typedef uint8_t CT_uint8_t;
typedef uint32_t CT_uint32_t;
typedef uint64_t CT_uint64_t;
typedef size_t CT_size_t;
typedef int CT_int;
typedef bool CT_bool;
#endif // !EFI

__END_DECLS

#endif /* _CORETRUST_CONFIG_H_ */
