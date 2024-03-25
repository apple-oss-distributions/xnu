/*
 * Copyright (c) 2022 Apple Inc. All rights reserved.
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

#ifndef _MACH_EXCLAVES_L4_H
#define _MACH_EXCLAVES_L4_H

#include <mach/exclaves.h>

/*
 * Equivalent versions of the subset of cL4 APIs needed for construction of
 * IPC message buffers & tags (with prefix changed L4_ -> Exclaves_L4_)
 */

__BEGIN_DECLS

#ifdef PRIVATE

#if defined(__LP64__)

/* -------------------------------------------------------------------------- */

/* Void data type */
typedef void Exclaves_L4_Void_t;

/** Boolean data type */;
typedef unsigned char Exclaves_L4_Bool_t;

/** Unsigned 32-bit data type */
typedef unsigned int Exclaves_L4_Word32_t;

/** Unsigned data type with native word length size */
typedef unsigned long Exclaves_L4_Word_t;

/** Data type for L4 system call return values */
typedef Exclaves_L4_Word_t Exclaves_L4_Error_t;

/**
 * Convert a value into a native word type
 *
 * @param x Value to convert
 * @return Value cast to the native word type
 */
#define Exclaves_L4_Word(x) ((Exclaves_L4_Word_t) (x))

/**
 * Convert a value into a 32-bit word type
 *
 * @param x Value to convert
 * @return Value cast to the 32-bit word type
 */
#define Exclaves_L4_Word32(x) ((Exclaves_L4_Word32_t) (x))

#define __Exclaves_L4_Packed __attribute__ ((__packed__))

/* Size of native word length in bits */
#define Exclaves_L4_WordBits (64)

/**
 * Produce a bitfield mask
 *
 * @param base Starting bit position within the created mask
 * @param bits Number of bits to set in the mask
 * @return A mask value
 */
#define Exclaves_L4_BfmW(base, bits) \
    (((~Exclaves_L4_Word(0)) >> (Exclaves_L4_WordBits - (bits))) << (base))

/**
 * Extract a value from a bitfield
 *
 * @param bitfield Bitfield contents to extract a value from
 * @param base Starting bit position of the value to extract
 * @param bits Number of bits for the value within the bitfield
 * @return The extracted value
 */
#define Exclaves_L4_BfxW(bitfield, base, bits) \
    (((bitfield) & Exclaves_L4_BfmW((base), (bits))) >> (base))

/**
 * Return a bitfield with a particular value inserted
 *
 * @param bitfield Bitfield current contents
 * @param base Starting bit position of the value to insert
 * @param bits Number of bits for the value within the bitfield
 * @param value Value to insert
 * @return The bitfield with the value inserted, overwriting any previous
 * value in the corresponding bits
 */
#define Exclaves_L4_BfiW(bitfield, base, bits, value) \
    (((bitfield) & (~Exclaves_L4_BfmW((base), (bits)))) | \
	(((Exclaves_L4_Word(value)) << (base)) & Exclaves_L4_BfmW((base), (bits))))

/**
 * Return an otherwise empty bitfield that had a value inserted
 *
 * @param base Starting bit position of the value to insert
 * @param bits Number of bits for the value within the bitfield
 * @param value Value to insert
 * @return The value encoded in the bitfield, with all other bits set to 0.
 */
#define Exclaves_L4_BfW(base, bits, value) \
    (Exclaves_L4_BfiW(Exclaves_L4_Word(0), (base), (bits), (value)))

/** Nil (zero) value */
#define Exclaves_L4_Nil ((Exclaves_L4_Word_t) 0)

/** Boolean true value */
#define Exclaves_L4_True ((Exclaves_L4_Bool_t) 1)

/** Boolean false value */
#define Exclaves_L4_False ((Exclaves_L4_Bool_t) 0)

/* -------------------------------------------------------------------------- */

/**
 * Create an Exclaves_L4_Error from a provided code and value
 *
 * @param code Specific Exclaves_L4_Error code
 * @param value Supplementary information providing more context about
 * the error
 * @return The complete error value
 */
#define Exclaves_L4_Error(code, value) (((Exclaves_L4_Word(value)) << 8) | (Exclaves_L4_Word(code)))

/**
 * Extract the error code from a constructed Exclaves_L4_Error_t
 *
 * @param error The error
 * @return The error code
 */
#define Exclaves_L4_ErrorCode(error) ((error) & (((Exclaves_L4_Word(1)) << 8) - 1))

/**
 * Extract the error value from a constructed Exclaves_L4_Error_t
 *
 * @param error The error
 * @return The error value
 */
#define Exclaves_L4_ErrorValue(error) ((error) >> 8)

/**
 * L4 error codes
 */

enum {
	Exclaves_L4_ErrorCodeSuccess,
	Exclaves_L4_ErrorCodePreempted,
	Exclaves_L4_ErrorCodeCanceled,
	Exclaves_L4_ErrorCodeTruncated,
	Exclaves_L4_ErrorCodeCapInvalid,
	Exclaves_L4_ErrorCodeSlotInvalid,
	Exclaves_L4_ErrorCodeMethodInvalid,
	Exclaves_L4_ErrorCodeArgumentInvalid,
	Exclaves_L4_ErrorCodeOperationInvalid,
	Exclaves_L4_ErrorCodePermissionInvalid,
	Exclaves_L4_ErrorCodeMax
};

#define Exclaves_L4_Success \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeSuccess, Exclaves_L4_Nil)
#define Exclaves_L4_Preempted \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodePreempted, Exclaves_L4_Nil)
#define Exclaves_L4_ErrorCanceled(reason) \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeCanceled, reason)
#define Exclaves_L4_ErrorTruncated \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeTruncated, Exclaves_L4_Nil)
#define Exclaves_L4_ErrorCapInvalid \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeCapInvalid, Exclaves_L4_Nil)
#define Exclaves_L4_ErrorSlotInvalid \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeSlotInvalid, Exclaves_L4_Nil)
#define Exclaves_L4_ErrorMethodInvalid \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeMethodInvalid, Exclaves_L4_Nil)
#define Exclaves_L4_ErrorArgumentInvalid(argument) \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeArgumentInvalid, argument)
#define Exclaves_L4_ErrorOperationInvalid \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodeOperationInvalid, Exclaves_L4_Nil)
#define Exclaves_L4_ErrorPermissionInvalid \
    Exclaves_L4_Error(Exclaves_L4_ErrorCodePermissionInvalid, Exclaves_L4_Nil)

/* -------------------------------------------------------------------------- */

/* Exclaves_L4_MessageTag_t
 *
 *  32                             0
 *  llllllllllllllll...nuuucccrrrrrr
 *
 * r: message registers (6 bits)
 * c: capability registers (3 bits)
 * u: unwrapped capabilities (3 bits)
 * n: non-blocking (1 bit)
 * l: label (16 bits)
 */

typedef Exclaves_L4_Word_t Exclaves_L4_MessageTag_t;

/* Exclaves_L4_MessageTag_Mrs */
#define Exclaves_L4_MessageTag_Mrs_Base 0
#define Exclaves_L4_MessageTag_Mrs_Bits 6

/* Exclaves_L4_MessageTag_Crs */
#define Exclaves_L4_MessageTag_Crs_Base 6
#define Exclaves_L4_MessageTag_Crs_Bits 3

/* Exclaves_L4_MessageTag_Unwrapped */
#define Exclaves_L4_MessageTag_Unwrapped_Base 9
#define Exclaves_L4_MessageTag_Unwrapped_Bits 3

/* Exclaves_L4_MessageTag_NonBlocking */
#define Exclaves_L4_MessageTag_NonBlocking_Base 12
#define Exclaves_L4_MessageTag_NonBlocking_Bits 1

/* Exclaves_L4_MessageTag_Label */
#define Exclaves_L4_MessageTag_Label_Base 16
#define Exclaves_L4_MessageTag_Label_Bits 16

static inline Exclaves_L4_Word_t
Exclaves_L4_MessageTag_Mrs(Exclaves_L4_MessageTag_t tag)
{
	return Exclaves_L4_Word(Exclaves_L4_BfxW(tag, Exclaves_L4_MessageTag_Mrs_Base,
	           Exclaves_L4_MessageTag_Mrs_Bits));
}

static inline Exclaves_L4_Word_t
Exclaves_L4_MessageTag_Crs(Exclaves_L4_MessageTag_t tag)
{
	return Exclaves_L4_Word(Exclaves_L4_BfxW(tag, Exclaves_L4_MessageTag_Crs_Base,
	           Exclaves_L4_MessageTag_Crs_Bits));
}

static inline Exclaves_L4_Word_t
Exclaves_L4_MessageTag_Unwrapped(Exclaves_L4_MessageTag_t tag)
{
	return Exclaves_L4_Word(Exclaves_L4_BfxW(tag, Exclaves_L4_MessageTag_Unwrapped_Base,
	           Exclaves_L4_MessageTag_Unwrapped_Bits));
}

static inline Exclaves_L4_Word_t
Exclaves_L4_MessageTag_Label(Exclaves_L4_MessageTag_t tag)
{
	return Exclaves_L4_Word(Exclaves_L4_BfxW(tag, Exclaves_L4_MessageTag_Label_Base,
	           Exclaves_L4_MessageTag_Label_Bits));
}

static inline Exclaves_L4_MessageTag_t
Exclaves_L4_MessageTag(Exclaves_L4_Word_t mrs, Exclaves_L4_Word_t crs, Exclaves_L4_Word_t label,
    Exclaves_L4_Bool_t nonblocking)
{
	Exclaves_L4_Word_t tag = (
		Exclaves_L4_BfW(Exclaves_L4_MessageTag_Mrs_Base,
		Exclaves_L4_MessageTag_Mrs_Bits, Exclaves_L4_Word(mrs)) |
		Exclaves_L4_BfW(Exclaves_L4_MessageTag_Crs_Base,
		Exclaves_L4_MessageTag_Crs_Bits, Exclaves_L4_Word(crs)) |
		Exclaves_L4_BfW(Exclaves_L4_MessageTag_NonBlocking_Base,
		Exclaves_L4_MessageTag_NonBlocking_Bits, Exclaves_L4_Word(nonblocking)) |
		Exclaves_L4_BfW(Exclaves_L4_MessageTag_Label_Base,
		Exclaves_L4_MessageTag_Label_Bits, Exclaves_L4_Word(label)));

	return (Exclaves_L4_MessageTag_t) tag;
}

/* -------------------------------------------------------------------------- */

/* Exclaves_L4_IpcBuffer_t  */

/* number of ipc buffer message registers */
#define Exclaves_L4_IpcBuffer_Mrs 56
/* numver of ipc buffer capability registers */
#define Exclaves_L4_IpcBuffer_Crs 4
/* ipc buffer size */
#define Exclaves_L4_IpcBuffer_Size (sizeof(Exclaves_L4_IpcBuffer_t))

/* ipc buffer object */
typedef struct __Exclaves_L4_Packed {
	/* message registers */
	Exclaves_L4_Word_t mr[Exclaves_L4_IpcBuffer_Mrs];
	/* source capability registers */
	Exclaves_L4_Word_t scr[Exclaves_L4_IpcBuffer_Crs];
	/* destination capability registers */
	Exclaves_L4_Word_t dcr[Exclaves_L4_IpcBuffer_Crs];
} Exclaves_L4_IpcBuffer_t;

/** Cast to a Exclaves IPC buffer pointer */
#define Exclaves_L4_IpcBuffer_Ptr(x) \
	(__unsafe_forge_single(Exclaves_L4_IpcBuffer_t *, (x)))

/* L4 IPC invocation message registers */
enum {
	Exclaves_L4_Ipc_Mr_Tag,
	Exclaves_L4_Ipc_Mr_Badge,
	Exclaves_L4_Ipc_Mr_Message
};

#ifdef KERNEL_PRIVATE

static inline Exclaves_L4_IpcBuffer_t *
Exclaves_L4_IpcBuffer(Exclaves_L4_Void_t)
{
	return Exclaves_L4_IpcBuffer_Ptr(exclaves_get_ipc_buffer());
}

#endif /* KERNEL_PRIVATE */

#ifdef MACH_KERNEL_PRIVATE

/* -------------------------------------------------------------------------- */

static inline Exclaves_L4_Word_t
Exclaves_L4_GetMr(Exclaves_L4_Word32_t mr)
{
	return Exclaves_L4_IpcBuffer()->mr[mr];
}

static inline Exclaves_L4_Void_t
Exclaves_L4_SetMr(Exclaves_L4_Word32_t mr, Exclaves_L4_Word_t word)
{
	Exclaves_L4_IpcBuffer()->mr[mr] = word;
}

static inline Exclaves_L4_Void_t
Exclaves_L4_SetMrs(Exclaves_L4_Word32_t mr, Exclaves_L4_Word32_t count,
    Exclaves_L4_Word_t * __counted_by(count)words)
{
	Exclaves_L4_IpcBuffer_t *ipcb = Exclaves_L4_IpcBuffer();

	for (Exclaves_L4_Word32_t offset = 0; offset < count; offset++) {
		ipcb->mr[mr + offset] = words[offset];
	}
}

static inline Exclaves_L4_Void_t
Exclaves_L4_GetMrs(Exclaves_L4_Word32_t mr, Exclaves_L4_Word32_t count,
    Exclaves_L4_Word_t * __counted_by(count)words)
{
	Exclaves_L4_IpcBuffer_t *ipcb = Exclaves_L4_IpcBuffer();

	for (Exclaves_L4_Word32_t offset = 0; offset < count; offset++) {
		words[offset] = ipcb->mr[mr + offset];
	}
}

static inline Exclaves_L4_Word_t
Exclaves_L4_GetCr(Exclaves_L4_Word32_t cr, Exclaves_L4_Bool_t dst)
{
	if (dst == Exclaves_L4_True) {
		return Exclaves_L4_IpcBuffer()->dcr[cr];
	} else {
		return Exclaves_L4_IpcBuffer()->scr[cr];
	}
}

static inline Exclaves_L4_Void_t
Exclaves_L4_SetCr(Exclaves_L4_Word32_t cr, Exclaves_L4_Word_t word, Exclaves_L4_Bool_t dst)
{
	if (dst == Exclaves_L4_True) {
		Exclaves_L4_IpcBuffer()->dcr[cr] = word;
	} else {
		Exclaves_L4_IpcBuffer()->scr[cr] = word;
	}
}

static inline Exclaves_L4_MessageTag_t
Exclaves_L4_GetMessageTag(Exclaves_L4_Void_t)
{
	return (Exclaves_L4_MessageTag_t) (Exclaves_L4_GetMr(Exclaves_L4_Ipc_Mr_Tag));
}

static inline Exclaves_L4_Void_t
Exclaves_L4_SetMessageTag(Exclaves_L4_MessageTag_t tag)
{
	Exclaves_L4_SetMr(Exclaves_L4_Ipc_Mr_Tag, Exclaves_L4_Word(tag));
}

static inline Exclaves_L4_Word_t
Exclaves_L4_GetMessageMr(Exclaves_L4_Word32_t mr)
{
	return Exclaves_L4_GetMr(Exclaves_L4_Ipc_Mr_Message + mr);
}

static inline Exclaves_L4_Void_t
Exclaves_L4_SetMessageMr(Exclaves_L4_Word32_t mr, Exclaves_L4_Word_t word)
{
	Exclaves_L4_SetMr((Exclaves_L4_Ipc_Mr_Message + mr), word);
}

#endif /* MACH_KERNEL_PRIVATE */

/* -------------------------------------------------------------------------- */

/* Private communication protocol between Libsyscall, xnu and xnu proxy */

/* Return value of the endpoint message forwarding call. */
#define EXCLAVES_XNU_PROXY_CR_RETVAL(ipcb) ((ipcb)->dcr[3])

/* identifiers for exclaves reachable through xnuproxy */
typedef enum : uint64_t {
	/* HelloExclaves: c-hello-exclave */
	EXCLAVES_XNUPROXY_EXCLAVE_HELLOEXCLAVE = 0,
	/* templated user_app */
	EXCLAVES_XNUPROXY_EXCLAVE_USERAPP,
	/* HelloTightbeam: swift-hello-exclave */
	EXCLAVES_XNUPROXY_EXCLAVE_HELLOTIGHTBEAM,
	/* HelloDrivers */
	EXCLAVES_XNUPROXY_EXCLAVE_HELLODRIVERS,
	/* HelloStorage */
	EXCLAVES_XNUPROXY_EXCLAVE_HELLOSTORAGE,
	/* templated user_app2 */
	EXCLAVES_XNUPROXY_EXCLAVE_USERAPP2,
	/* templated user_app3 */
	EXCLAVES_XNUPROXY_EXCLAVE_USERAPP3,
	/* audio */
	EXCLAVES_XNUPROXY_EXCLAVE_AUDIODRIVER,
	/* HelloDriverInterrupts */
	EXCLAVES_XNUPROXY_EXCLAVE_HELLODRIVERINTERRUPTS,
	/* ExclaveDriverKit */
	EXCLAVES_XNUPROXY_EXCLAVE_EXCLAVEDRIVERKIT,
	/* SecureRTBuddy for AOP */
	EXCLAVES_XNUPROXY_EXCLAVE_SECURERTBUDDY_AOP,
	/* SecureRTBuddy for DCP */
	EXCLAVES_XNUPROXY_EXCLAVE_SECURERTBUDDY_DCP,
	/* conclave launcher control */
	EXCLAVES_XNUPROXY_EXCLAVE_CONCLAVECONTROL,
	/* conclave launcher control */
	EXCLAVES_XNUPROXY_EXCLAVE_CONCLAVEDEBUG,
	/* SecureRTBuddy EDK connection for AOP */
	EXCLAVES_XNUPROXY_EXCLAVE_SECURERTBUDDY_AOP_EDK,
	/* SecureRTBuddy EDK connection for DCP */
	EXCLAVES_XNUPROXY_EXCLAVE_SECURERTBUDDY_DCP_EDK,
} exclaves_xnuproxy_exclaves_t;

typedef enum : uint32_t {
	EXCLAVES_XNUPROXY_TEST_BUF1 = 1,
	EXCLAVES_XNUPROXY_TEST_BUF2,
	EXCLAVES_XNUPROXY_TEST_BUF3,
	EXCLAVES_XNUPROXY_TEST_BUF4,
	/* 5 is empty */
	EXCLAVES_XNUPROXY_NAMED_BUFFER_STORAGE_BUF_1 = 6,
	EXCLAVES_XNUPROXY_NAMED_BUFFER_STORAGE_BUF_2 = 7,

	EXCLAVES_XNUPROXY_LAST_STATIC_BUF = 47,
	EXCLAVES_XNUPROXY_TEST_DYN_BUF1,
	EXCLAVES_XNUPROXY_TEST_DYN_BUF2,
} exclaves_named_buffer_id_t;

#endif /* defined(__LP64__) */

#endif /* PRIVATE */

__END_DECLS

#endif /* _MACH_EXCLAVES_L4_H */
