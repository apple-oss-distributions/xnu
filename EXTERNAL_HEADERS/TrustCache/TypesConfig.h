#ifndef libTrustCache_TypesConfig_h
#define libTrustCache_TypesConfig_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <TrustCache/Types.h>

#if XNU_KERNEL_PRIVATE
/*
 * The AppleImage4 API definitions are accessed through the 'img4if' indirection
 * layer within XNU itself. Kernel extensions can access them directly from the
 * AppleImage4 headers.
 */
#include <libkern/img4/interface.h>
#endif

#if !XNU_KERNEL_PRIVATE
/*
 * XNU does not make this header available and uses different availability macros
 * than kernel extensions or base user-space applications.
 */
#include <TargetConditionals.h>
#endif

#pragma mark Chip Environments

static const img4_chip_t*
chipEnvironmentPersonalized(void) {
    return img4_chip_select_personalized_ap();
}

static const img4_chip_t*
chipEnvironmentCategorized(void) {
    return img4_chip_select_categorized_ap();
}

static const img4_chip_t*
chipEnvironmentGlobalFF00(void) {
    return IMG4_CHIP_AP_SOFTWARE_FF00;
}

static const img4_chip_t*
chipEnvironmentGlobalFF01(void) {
    return IMG4_CHIP_AP_SOFTWARE_FF01;
}

static const img4_chip_t*
chipEnvironmentGlobalFF06(void) {
    return IMG4_CHIP_AP_SOFTWARE_FF06;
}

static const img4_chip_t*
chipEnvironmentEphemeralCryptex(void) {
    return IMG4_CHIP_AP_SUPPLEMENTAL;
}

static const img4_chip_t*
chipEnvironmentCryptex1Boot(void) {
#if IMG4_API_VERSION >= 20211126
    return img4_chip_select_cryptex1_boot();
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentCryptex1PreBoot(void) {
#if IMG4_API_VERSION >= 20211126
    return img4_chip_select_cryptex1_preboot();
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentCryptex1MobileAsset(void) {
#if IMG4_API_VERSION >= 20211126
    return IMG4_CHIP_CRYPTEX1_ASSET;
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentSafariDownlevel(void) {
#if IMG4_API_VERSION >= 20211126
    return IMG4_CHIP_CRYPTEX1_BOOT_REDUCED;
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentSupplemental(void) {
    return IMG4_CHIP_AP_SUPPLEMENTAL;
}

static const img4_chip_t*
chipEnvironmentCryptex1Generic(void) {
#if IMG4_API_VERSION >= 20221202
    return IMG4_CHIP_CRYPTEX1_GENERIC;
#else
    return NULL;
#endif
}

static const img4_chip_t*
chipEnvironmentCryptex1GenericSupplemental(void) {
#if IMG4_API_VERSION >= 20221202
    return IMG4_CHIP_CRYPTEX1_GENERIC_SUPPLEMENTAL;
#else
    return NULL;
#endif
}

#pragma mark Nonce Domains

static const img4_nonce_domain_t*
nonceDomainTrustCache(void) {
    return IMG4_NONCE_DOMAIN_TRUST_CACHE;
}

static const img4_nonce_domain_t*
nonceDomainDDI(void) {
    return IMG4_NONCE_DOMAIN_DDI;
}

static const img4_nonce_domain_t*
nonceDomainCryptex(void) {
    return IMG4_NONCE_DOMAIN_CRYPTEX;
}

static const img4_nonce_domain_t*
nonceDomainEphemeralCryptex(void) {
    return IMG4_NONCE_DOMAIN_EPHEMERAL_CRYPTEX;
}

static const img4_nonce_domain_t*
nonceDomainPDI(void) {
    return IMG4_NONCE_DOMAIN_PDI;
}

#pragma mark Firmware Flags

static img4_firmware_flags_t
firmwareFlagsDTRS(void) {
    return IMG4_FIRMWARE_FLAG_RESPECT_AMNM;
}

static img4_firmware_flags_t
firmwareFlagsSplat(void) {
#if XNU_TARGET_OS_OSX && (defined(__arm__) || defined(__arm64__))
    return IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE;
#elif defined(TARGET_OS_OSX) && TARGET_OS_OSX && (TARGET_CPU_ARM || TARGET_CPU_ARM64)
    return IMG4_FIRMWARE_FLAG_SUBSEQUENT_STAGE;
#else
    return IMG4_FIRMWARE_FLAG_INIT;
#endif
}

#pragma mark Type Configuration

typedef struct _TrustCacheTypeConfig {
    /* Chip environment to use for validation */
    const img4_chip_t* (*chipEnvironment)(void);

    /* Nonce domain for anti-replay */
    const img4_nonce_domain_t* (*nonceDomain)(void);

    /* Four CC identifier for this type */
    img4_4cc_t fourCC;

    /* Firmware flags to add for this configuration */
    img4_firmware_flags_t (*firmwareFlags)(void);

    /*
     * Higher level policy imposes restrictions on which process can load
     * which trust cache. These restrictions are enforced through the use
     * of the entitlement "com.apple.private.pmap.load-trust-cache". The
     * value here is the required value of the above entitlement.
     */
    const char *entitlementValue;
} TrustCacheTypeConfig_t;

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wfour-char-constants"

static const TrustCacheTypeConfig_t TCTypeConfig[kTCTypeTotal] = {
    /* Static trust caches are loaded as raw modules */
    [kTCTypeStatic] = {
        .chipEnvironment = NULL,
        .nonceDomain = NULL,
        .fourCC = 0,
        .firmwareFlags = NULL,
        .entitlementValue = NULL
    },

    /* Engineering trust caches are loaded as raw modules */
    [kTCTypeEngineering] = {
        .chipEnvironment = NULL,
        .nonceDomain = NULL,
        .fourCC = 0,
        .firmwareFlags = NULL,
        .entitlementValue = NULL
    },

    /* Legacy trust caches are loaded as raw modules */
    [kTCTypeLegacy] = {
        .chipEnvironment = NULL,
        .nonceDomain = NULL,
        .fourCC = 0,
        .firmwareFlags = NULL,
        .entitlementValue = NULL
    },

    [kTCTypeDTRS] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = NULL,
        .fourCC = 'dtrs',
        .firmwareFlags = firmwareFlagsDTRS,
        .entitlementValue = "personalized.engineering-root"
    },

    [kTCTypeLTRS] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainTrustCache,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.trust-cache"
    },

    [kTCTypePersonalizedDiskImage] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainPDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.pdi"
    },

    [kTCTypeDeveloperDiskImage] = {
        .chipEnvironment = chipEnvironmentCategorized,
        .nonceDomain = nonceDomainDDI,
        .fourCC = 'trdv',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.ddi"
    },

    [kTCTypeLTRSWithDDINonce] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainDDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.ddi"
    },

    [kTCTypeCryptex] = {
        .chipEnvironment = chipEnvironmentPersonalized,
        .nonceDomain = nonceDomainCryptex,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.cryptex-research"
    },

    [kTCTypeEphemeralCryptex] = {
        .chipEnvironment = chipEnvironmentEphemeralCryptex,
        .nonceDomain = nonceDomainEphemeralCryptex,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.ephemeral-cryptex"
    },

    [kTCTypeUpdateBrain] = {
        .chipEnvironment = chipEnvironmentGlobalFF00,
        .nonceDomain = NULL,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "global.ota-update-brain"
    },

    [kTCTypeInstallAssistant] = {
        .chipEnvironment = chipEnvironmentGlobalFF01,
        .nonceDomain = NULL,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "global.install-assistant"
    },

    [kTCTypeBootabilityBrain] = {
        .chipEnvironment = chipEnvironmentGlobalFF06,
        .nonceDomain = NULL,
        .fourCC = 'trbb',
        .firmwareFlags = NULL,
        .entitlementValue = "global.bootability-brain"
    },

    [kTCTypeCryptex1BootOS] = {
        .chipEnvironment = chipEnvironmentCryptex1Boot,
        .nonceDomain = NULL,
        .fourCC = 'trcs',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.boot.os"
    },

    [kTCTypeCryptex1BootApp] = {
        .chipEnvironment = chipEnvironmentCryptex1Boot,
        .nonceDomain = NULL,
        .fourCC = 'trca',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.boot.app"
    },

    [kTCTypeCryptex1PreBootApp] = {
        .chipEnvironment = chipEnvironmentCryptex1PreBoot,
        .nonceDomain = NULL,
        .fourCC = 'trca',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.preboot.app"
    },

    [kTCTypeGlobalDiskImage] = {
        .chipEnvironment = chipEnvironmentGlobalFF00,
        .nonceDomain = NULL,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "global.pdi"
    },

    [kTCTypeMobileAssetBrain] = {
        .chipEnvironment = chipEnvironmentCryptex1MobileAsset,
        .nonceDomain = NULL,
        .fourCC = 'trab',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.mobile-asset-brain"
    },

    [kTCTypeSafariDownlevel] = {
        .chipEnvironment = chipEnvironmentSafariDownlevel,
        .nonceDomain = NULL,
        .fourCC = 'trca',
        .firmwareFlags = NULL,
        .entitlementValue = "cryptex1.safari-downlevel"
    },

    [kTCTypeCryptex1PreBootOS] = {
        .chipEnvironment = chipEnvironmentCryptex1PreBoot,
        .nonceDomain = NULL,
        .fourCC = 'trcs',
        .firmwareFlags = firmwareFlagsSplat,
        .entitlementValue = "cryptex1.preboot.os"
    },

    [kTCTypeSupplementalPersistent] = {
        .chipEnvironment = chipEnvironmentSupplemental,
        .nonceDomain = nonceDomainDDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.supplemental-persistent"
    },

    [kTCTypeSupplementalEphemeral] = {
        .chipEnvironment = chipEnvironmentSupplemental,
        .nonceDomain = nonceDomainPDI,
        .fourCC = 'ltrs',
        .firmwareFlags = NULL,
        .entitlementValue = "personalized.supplemental-ephemeral"
    },

    [kTCTypeCryptex1Generic] = {
        .chipEnvironment = chipEnvironmentCryptex1Generic,
        .nonceDomain = NULL,
        .fourCC = 'gtcd',
        .firmwareFlags = NULL,
        .entitlementValue = "cryptex1.generic"
    },

    [kTCTypeCryptex1GenericSupplemental] = {
        .chipEnvironment = chipEnvironmentCryptex1GenericSupplemental,
        .nonceDomain = NULL,
        .fourCC = 'gtcd',
        .firmwareFlags = NULL,
        .entitlementValue = "cryptex1.generic.supplemental"
    }
};

#pragma GCC diagnostic pop

__END_DECLS
#endif /* libTrustCache_TypesConfig_h */
