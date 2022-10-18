/* Copyright (c) (2010-2012,2014-2021) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCDIGEST_H_
#define _CORECRYPTO_CCDIGEST_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccn.h>

/* To malloc a digest context for a given di, use malloc(ccdigest_di_size(di))
   and assign the result to a pointer to a struct ccdigest_ctx. */
struct ccdigest_ctx {
    uint8_t state[1];
} CC_ALIGNED(8);

typedef struct ccdigest_ctx *ccdigest_ctx_t;

struct ccdigest_state {
    uint8_t state[1];
} CC_ALIGNED(8);

typedef struct ccdigest_state *ccdigest_state_t;

struct ccdigest_info {
    size_t output_size;
    size_t state_size;
    size_t block_size;
    size_t oid_size;
    const unsigned char *oid;
    const void *initial_state;
    void(* CC_SPTR(ccdigest_info, compress))(ccdigest_state_t state, size_t nblocks,
                    const void *data);
    void(* CC_SPTR(ccdigest_info, final))(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                 unsigned char *digest);
    cc_impl_t impl;
};

/* Return sizeof a ccdigest_ctx for a given size_t _state_size_ and
   size_t _block_size_. */
#define ccdigest_ctx_size(_state_size_, _block_size_)  ((_state_size_) + sizeof(uint64_t) + (_block_size_) + sizeof(unsigned int))
/* Return sizeof a ccdigest_ctx for a given struct ccdigest_info *_di_. */
#define ccdigest_di_size(_di_)  (ccdigest_ctx_size((_di_)->state_size, (_di_)->block_size))

/* Declare a ccdigest_ctx for a given size_t _state_size_ and
   size_t _block_size_, named _name_.  Can be used in structs or on the
   stack. */
#define ccdigest_ctx_decl(_state_size_, _block_size_, _name_)  cc_ctx_decl(struct ccdigest_ctx, ccdigest_ctx_size(_state_size_, _block_size_), _name_)
#define ccdigest_ctx_clear(_state_size_, _block_size_, _name_) cc_clear(ccdigest_ctx_size(_state_size_, _block_size_), _name_)
/* Declare a ccdigest_ctx for a given size_t _state_size_ and
   size_t _block_size_, named _name_.  Can be used on the stack. */
#define ccdigest_di_decl(_di_, _name_)  cc_ctx_decl_vla(struct ccdigest_ctx, ccdigest_di_size(_di_), _name_)
#define ccdigest_di_clear(_di_, _name_) cc_clear(ccdigest_di_size(_di_), _name_)

/* Digest context field accessors.  Consider the implementation private. */
#define ccdigest_state_u8(_di_, _ctx_)   ccdigest_u8(ccdigest_state((_di_), (_ctx_)))
#define ccdigest_state_u32(_di_, _ctx_)  ccdigest_u32(ccdigest_state((_di_), (_ctx_)))
#define ccdigest_state_u64(_di_, _ctx_)  ccdigest_u64(ccdigest_state((_di_), (_ctx_)))
#define ccdigest_state_ccn(_di_, _ctx_)  ccdigest_ccn(ccdigest_state((_di_), (_ctx_)))

#define ccdigest_nbits(_di_, _ctx_)      (*((uint64_t *)((ccdigest_ctx_t)(_ctx_))->state))
#define ccdigest_state(_di_, _ctx_)      ((ccdigest_state_t)(((ccdigest_ctx_t)(_ctx_))->state + sizeof(uint64_t)))
#define ccdigest_data(_di_, _ctx_)       (((ccdigest_ctx_t)(_ctx_))->state + (_di_)->state_size + sizeof(uint64_t))
#define ccdigest_num(_di_, _ctx_)        (*((unsigned int *)(((ccdigest_ctx_t)(_ctx_))->state + (_di_)->state_size + sizeof(uint64_t) + (_di_)->block_size)))

/* Digest state field accessors.  Consider the implementation private. */
#define ccdigest_u8(_state_)             ((uint8_t *)((ccdigest_state_t)(_state_)))
#define ccdigest_u32(_state_)            ((uint32_t *)((ccdigest_state_t)(_state_)))
#define ccdigest_u64(_state_)            ((uint64_t *)((ccdigest_state_t)(_state_)))
#define ccdigest_ccn(_state_)            ((cc_unit *)((ccdigest_state_t)(_state_)))

void ccdigest_init(const struct ccdigest_info *di, ccdigest_ctx_t ctx);
void ccdigest_update(const struct ccdigest_info *di, ccdigest_ctx_t ctx,
                     size_t len, const void *data);

CC_INLINE
void ccdigest_final(const struct ccdigest_info *di, ccdigest_ctx_t ctx, unsigned char *digest)
{
    di->final(di,ctx,digest);
}

void ccdigest(const struct ccdigest_info *di, size_t len,
              const void *data, void *digest);

#define OID_DEF(_VALUE_)  ((const unsigned char *)_VALUE_)

// https://csrc.nist.gov/projects/computer-security-objects-register/algorithm-registration#Hash
#define CC_DIGEST_OID_MD2           OID_DEF("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x02")
#define CC_DIGEST_OID_MD4           OID_DEF("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x04")
#define CC_DIGEST_OID_MD5           OID_DEF("\x06\x08\x2A\x86\x48\x86\xF7\x0D\x02\x05")
#define CC_DIGEST_OID_SHA1          OID_DEF("\x06\x05\x2b\x0e\x03\x02\x1a")
#define CC_DIGEST_OID_SHA224        OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04")
#define CC_DIGEST_OID_SHA256        OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01")
#define CC_DIGEST_OID_SHA384        OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02")
#define CC_DIGEST_OID_SHA512        OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03")
#define CC_DIGEST_OID_SHA512_256    OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x06")
#define CC_DIGEST_OID_RMD160        OID_DEF("\x06\x05\x2B\x24\x03\x02\x01")
#define CC_DIGEST_OID_SHA3_224      OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x07")
#define CC_DIGEST_OID_SHA3_256      OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x08")
#define CC_DIGEST_OID_SHA3_384      OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x09")
#define CC_DIGEST_OID_SHA3_512      OID_DEF("\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x0A")

// Provide current maximum sizes for block and state in order to prevent the
// need for dynamic allocation of context or many macro accessor functions.
#define MAX_DIGEST_BLOCK_SIZE 144  // Maximum block size is that of SHA3-224
#define MAX_DIGEST_STATE_SIZE 200  // SHA-3 state is 1600 bits
#define MAX_DIGEST_OUTPUT_SIZE 64

#endif /* _CORECRYPTO_CCDIGEST_H_ */
