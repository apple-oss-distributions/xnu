#ifndef libTrustCache_RawTypes_h
#define libTrustCache_RawTypes_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>
#include <corecrypto/ccsha1.h>

/*
 * CDHashes in the trust cache are always truncated to the length of a SHA1 hash.
 */
#define kTCEntryHashSize CCSHA1_OUTPUT_SIZE

/* UUIDs are always 16 bytes */
#define kUUIDSize 16

/* Versions supported by the library */
enum {
    kTCVersion0 = 0x0,
    kTCVersion1 = 0x1,
    kTCVersion2 = 0x2,

    kTCVersionTotal,
};

/* Flags for the trust cache look ups */
enum {
    kTCFlagAMFID = 0x01,
    kTCFlagANEModel = 0x02,
};

typedef struct _TrustCacheModuleBase {
    /* The version for this trust cache module */
    uint32_t version;
} __attribute__((packed)) TrustCacheModuleBase_t;

#pragma mark Trust Cache Version 0

typedef uint8_t TrustCacheEntry0_t[kTCEntryHashSize];

typedef struct _TrustCacheModule0 {
    /* Must be 0 */
    uint32_t version;

    /* ID which uniquely identifies the trust cache */
    uint8_t uuid[kUUIDSize];

    /* The number of entries present in the trust cache */
    uint32_t numEntries;

    /* Dynamic data containing all the entries */
    TrustCacheEntry0_t entries[0];
} __attribute__((packed)) TrustCacheModule0_t;

#pragma mark Trust Cache Version 1

typedef struct _TrustCacheEntry1 {
    uint8_t CDHash[kTCEntryHashSize];
    uint8_t hashType;
    uint8_t flags;
} __attribute__((packed)) TrustCacheEntry1_t;

typedef struct _TrustCacheModule1 {
    /* Must be 1 */
    uint32_t version;

    /* ID which uniquely identifies the trust cache */
    uint8_t uuid[kUUIDSize];

    /* The number of entries present in the trust cache */
    uint32_t numEntries;

    /* Dynamic data containing all the entries */
    TrustCacheEntry1_t entries[0];
} __attribute__((packed)) TrustCacheModule1_t;

#pragma mark Trust Cache Version 2

typedef struct _TrustCacheEntry2 {
    uint8_t CDHash[kTCEntryHashSize];
    uint8_t hashType;
    uint8_t flags;
    uint8_t constraintCategory;
    uint8_t reserved0;
} __attribute__((packed)) TrustCacheEntry2_t;

typedef struct _TrustCacheModule2 {
    /* Must be 2 */
    uint32_t version;

    /* ID which uniquely identifies the trust cache */
    uint8_t uuid[kUUIDSize];

    /* The number of entries present in the trust cache */
    uint32_t numEntries;

    /* Dynamic data containing all the entries */
    TrustCacheEntry2_t entries[0];
} __attribute__((packed)) TrustCacheModule2_t;

__END_DECLS
#endif /* libTrustCache_RawTypes_h */
