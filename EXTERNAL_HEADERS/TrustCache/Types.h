#ifndef libTrustCache_Types_h
#define libTrustCache_Types_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>
#include <img4/firmware.h>
#include <TrustCache/RawTypes.h>

typedef uint8_t TCType_t;
enum {
    /*
     * These types of trust caches are always loaded as modules. Their validation
     * is done externally by upper-level software.
     *
     * Static trust caches are bundled with the operating system and are the primary
     * method of denoting platform trust. Engineering trust caches are similar to
     * static trust caches except that they can be created by engineers at their
     * desk as a root for a static trust cache. Legacy trust caches are image3 signed
     * modules. This library does not support validating image3 signatures, so it
     * accepts the trust caches only as direct modules. These are still considered
     * loadable trust caches.
     */
    kTCTypeStatic = 0x00,
    kTCTypeEngineering = 0x01,
    kTCTypeLegacy = 0x02,

    /*
     * Do NOT change the order of the types listed here. This header is shared across
     * a variety of projects and they update at different cadences. Adding a new type
     * requires appending to the end of the enumeration, instead of insertion in the
     * middle somewhere.
     */

    /*
     * Type: Personalized
     * These are engineering roots which are only ever valid for development devices.
     * These can be created by engineers at their desks for testing software.
     */
    kTCTypeDTRS = 0x03,

    /*
     * Type: Personalized
     * These are loadable trust caches which are viable for all kinds of devices and
     * can be used for testing, but also for shipping code in production devices.
     */
    kTCTypeLTRS = 0x04,

    /*
     * Type: Personalized
     * Used by disk images which are used to supply platform code for a number of use
     * cases, including the multidude of disk images supplied for engineering use-cases
     * such as the factoey disk image.
     */
    kTCTypePersonalizedDiskImage = 0x05,

    /*
     * Type: Categorized
     * Developer disk images which are personalized per device. These have a different
     * tag than standard loadable trust caches and helps differentiate them. However,
     * these were never productionized and are for all purposes, retired.
     */
    kTCTypeDeveloperDiskImage = 0x06,

    /*
     * Type: Personalized
     * These trust caches are similar to a personalized LTRS trust cache type except
     * they are personalized against a long lived nonce, allowing these to remain
     * useable across reboots of the system.
     */
    kTCTypeLTRSWithDDINonce = 0x07,

    /*
     * Type: Personalized
     * These trust cache types are used to authenticate code shipped in Cryptexes for
     * security research devices. Outside of the SRD, these are also used in some data
     * center use cases which deploy code through Cryptexes.
     */
    kTCTypeCryptex = 0x08,

    /*
     * Type: Personalized (against supplemental root)
     * These are special trust caches which validate against a supplemental root beyond
     * Tatsu. These are only meant for special deployments within some data centers.
     *
     * NOTE: This type is deprecated in favor of the newer Supplemental Persistent
     * and Supplemental Ephemeral types.
     */
    kTCTypeEphemeralCryptex = 0x09,

    /*
     * Type: Global
     * OTA updates ship an update brain to assist with the OS update. The brain is some
     * code with platform privileges which can do whatever the current OS needs it to do
     * in order to update the system.
     */
    kTCTypeUpdateBrain = 0x0A,

    /*
     * Type: Global
     * Trust caches which are loaded by the Install Assistant on macOS in order to help
     * with installing macOS.
     */
    kTCTypeInstallAssistant = 0x0B,

    /*
     * Type: Global
     * These are used by macOS systems to ship a bootability brain. The bootability brain
     * is a piece of code which helps determine if macOS systems of a different version
     * are bootable or not. The brain is useful because the logic for determining that a
     * system is bootable or not differs with each release.
     */
    kTCTypeBootabilityBrain = 0x0C,

    /*
     * Type: Personalized (against Cryptex 1 Boot/Preboot environments)
     * These trust cache types are used by SPLAT at different stages of the boot pipeline
     * for loading code responsible for system boot up, such as the shared cache.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1BootOS = 0x0D,
    kTCTypeCryptex1BootApp = 0x0E,
    kTCTypeCryptex1PreBootApp = 0x0F,

    /*
     * Type: Global
     * These are disk images which are globally signed against the FF00 chip environment.
     * They are used when disk images want to supply code for devices across the fleet
     * without requiring individual personalization for each.
     *
     * The developer disk image is supplied through this mechanism as well, as of January
     * 5th, 2022.
     */
    kTCTypeGlobalDiskImage = 0x10,

    /*
     * Type: Personalized (Cryptex1 mobile asset brain)
     * The mobile asset brain contains the core logic for mobileassetd, which is a system
     * daemon responsible for downloading and maintaining assets on the device. The brain
     * is meant to be back-deployable, which is what the trust cache helps with.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeMobileAssetBrain = 0x11,

    /*
     * Type: Personalized (Cryptex1 boot reduced)
     * Safari is backported to older builds. Since Safari is now moving to a SPLAT based
     * mount volume, we need to support loading a trust cache which is used to mount and
     * run Safari from the future.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeSafariDownlevel = 0x12,

    /*
     * Type: Personalized (Cryptex 1 Preboot)
     * This trust cache type is used for the semi-SPLAT use-case for loading the new dyld
     * shared cache onto the platform, along with some other system libraries. This is
     * only required for macOS.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1PreBootOS = 0x13,

    /*
     * Type: Personalized (Supplemental Root)
     * Persistent trust caches which are signed by an authority different from Tatsu.
     * These are only required for deployment on darwinOS platforms.
     */
    kTCTypeSupplementalPersistent = 0x14,

    /*
     * Type: Personalized (Supplemental Root)
     * Ephemeral trust caches which are signed by an authority different from Tatsu.
     * These are only required for deployment on darwinOS platforms.
     */
    kTCTypeSupplementalEphemeral = 0x15,

    /*
     * Type: Personalized (Cryptex1 Generic)
     * This type can be used by the assortment of PDIs we ship. Each PDI train can opt
     * into allocating a Cryptex1 sub-type for itself, and then ship on the OS being
     * signed by the Cryptex1 generic environment. This allows the PDI to adopt Cryptex1
     * personalization without requiring a new bespoke trust cache type.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1Generic = 0x16,

    /*
     * Type: Personalized (Cryptex1 Generic Supplemental)
     * Similar to the kTCTypeCryptex1Generic type except the manifest is signed by the
     * supplemental root of trust. Only viable for some data center use-cases.
     *
     * The personalization uses a Cryptex1 nonce domain, which is embedded within the
     * manifest itself.
     */
    kTCTypeCryptex1GenericSupplemental = 0x17,

    /*
     * Type: Personalized (Cryptex1 mobile asset brain)
     * This is exactly the same as the kTCTypeMobileAssetBrain type, except this using
     * the PDI nonce. The PDI nonce rolls every boot, and having a trust cache type
     * here helps create an asset brain personalization which works on the current
     * boot, but becomes invalid after a reboot, thus ensuring the brain which was
     * personalized will only remain valid for the current OS (this type is used by
     * the update brain which performs an OTA).
     */
    kTCTypeMobileAssetBrainEphemeral = 0x18,

    kTCTypeTotal,

    /* Invalid type */
    kTCTypeInvalid = 0xFF,
};

/* Availability macros for different trust cache types */
#define kLibTrustCacheHasCryptex1BootOS 1
#define kLibTrustCacheHasCryptex1BootApp 1
#define kLibTrustCacheHasCryptex1PreBootApp 1
#define kLibTrustCacheHasMobileAssetBrain 1
#define kLibTrustCacheHasSafariDownlevel 1
#define kLibTrustCacheHasCryptex1PreBootOS 1
#define kLibTrustCacheHasSupplementalPersistent 1
#define kLibTrustCacheHasSupplementalEphemeral 1
#define kLibTrustCacheHasCryptex1Generic 1
#define kLibTrustCacheHasCryptex1GenericSupplemental 1
#define kLibTrustCacheHasMobileAssetBrainEphemeral 1

typedef struct _TrustCache {
    /* Linked list linkage for the trust cache */
    struct _TrustCache *next;
    struct _TrustCache *prev;

    /* The type of this trust cache */
    TCType_t type;

    /* TODO: Add reference counts when we support unloading */

    /* The trust cache module itself */
    size_t moduleSize;
    const TrustCacheModuleBase_t *module;
} TrustCache_t;

typedef uint8_t TCQueryType_t;
enum {
    /* Query all types of trust caches in the runtime */
    kTCQueryTypeAll = 0x00,

    /* Static query type includes engineering trust caches */
    kTCQueryTypeStatic = 0x01,

    /* Most first party trust cache types are loadable ones */
    kTCQueryTypeLoadable = 0x02,

    kTCQueryTypeTotal,
};

typedef uint64_t TCCapabilities_t;
enum {
    /* Supports no capabilities */
    kTCCapabilityNone = 0,

    /* Supports the hash type field */
    kTCCapabilityHashType = (1 << 0),

    /* Supports the flags field */
    kTCCapabilityFlags = (1 << 1),

    /* Supports the constraints category field */
    kTCCapabilityConstraintsCategory = (1 << 2),
};

typedef struct _TrustCacheQueryToken {
    /* Trust cache where query was found */
    const TrustCache_t *trustCache;

    /* Entry within the trust cache where query was found */
    const void *trustCacheEntry;
} TrustCacheQueryToken_t;

/*
 * The runtime data structure is setup in a very special way. To make use of HW mitigations
 * offered by the silicon, the runtime can be placed in a region which is locked down by the
 * HW at some commit point. This theoretically allows the static and the engineering trust
 * caches to be locked down and immutable if the storage for the trust cache data structure
 * is also allocated within this same immutable memory segment.
 *
 * At the same time, we need to be able to support dynamically loaded trust caches on the
 * system. We can't keep a list head within the runtime for these trust caches, since that
 * head will be locked down when the runtime is locked, preventing us from adding a new link
 * in the chain. To solve this, the runtime instead stores a pointer to a wrapped data structure.
 * This pointer itself is locked down and can't be changed, but the contents of the wrapped
 * structure are mutable, making it a good place to store the linked list head.
 */

/* Data structure expected to be stored within mutable memory */
typedef struct _TrustCacheMutableRuntime {
    /* Loadable trust caches on the system */
    TrustCache_t *loadableTCHead;
} TrustCacheMutableRuntime_t;

/* Data structure expected to be stored within immutable memory */
typedef struct _TrustCacheRuntime {
    /* Runtime to use for image 4 object verification */
    const img4_runtime_t *image4RT;

    /* Configuration for trust cache types */
    bool allowSecondStaticTC;
    bool allowEngineeringTC;
    bool allowLegacyTC;

    /* Static trust cache for the system */
    TrustCache_t *staticTCHead;

    /* Engineering trust caches for the system */
    TrustCache_t *engineeringTCHead;

    /* Mutable runtime instance */
    TrustCacheMutableRuntime_t *mutableRT;
} TrustCacheRuntime_t;

__END_DECLS
#endif /* libTrustCache_Types_h */
