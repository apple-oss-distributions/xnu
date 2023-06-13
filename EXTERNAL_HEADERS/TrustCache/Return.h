#ifndef libTrustCache_Return_h
#define libTrustCache_Return_h

#include <sys/cdefs.h>
__BEGIN_DECLS

#include <stdint.h>

/* Components which can return information from the library */
enum {
    kTCComponentLoadModule = 0x00,
    kTCComponentLoad = 0x01,
    kTCComponentImage4Validate = 0x02,
    kTCComponentImage4Callback = 0x03,
    kTCComponentConstructInvalid = 0x04,
    kTCComponentCheckRuntimeForUUID = 0x05,
    kTCComponentExtractModule = 0x06,
    kTCComponentGetUUID = 0x07,
    kTCComponentGetModule = 0x08,

    /* Query Functions */
    kTCComponentQuery = 0x10,
    kTCComponentQueryChain = 0x11,
    kTCComponentQueryRuntime = 0x12,
    kTCComponentQueryTCType = 0x13,
    kTCComponentQueryHashType = 0x14,
    kTCComponentQueryFlags = 0x15,
    kTCComponentQueryConstraintCategory = 0x16,

    /* Module based */
    kTCComponentQueryModule = 0x40,
    kTCComponentValidateModule = 0x41,
    kTCComponentQueryModule0 = 0x42,
    kTCComponentValidateModule0 = 0x43,
    kTCComponentQueryModule1 = 0x44,
    kTCComponentValidateModule1 = 0x45,
    kTCComponentQueryModule2 = 0x46,
    kTCComponentValidateModule2 = 0x47,
    kTCComponentModuleCapabilities = 0x48,

    /* Other functions which can return a value */
    kTCComponentLinkedListAddHead = 0x80,
    kTCComponentLinkedListRemove = 0x81,
    kTCComponentExtractImage4Payload = 0x82,

    /* Cannot exceed this value */
    kTCComponentTotal = 0xFF,
};

/* Error types which can be returned from the library */
enum {
    kTCReturnSuccess = 0x00,

    /* Generic error condition - avoid using this */
    kTCReturnError = 0x01,

    /* Specific error conditions */
    kTCReturnOverflow = 0x20,
    kTCReturnUnsupported = 0x21,
    kTCReturnInvalidModule = 0x22,
    kTCReturnDuplicate = 0x23,
    kTCReturnNotFound = 0x24,
    kTCReturnInvalidArguments = 0x25,
    kTCReturnInsufficientLength = 0x26,
    kTCReturnNotPermitted = 0x27,
    kTCReturnLinkedListCorrupted = 0x28,

    /* Image 4 return errors */
    kTCReturnImage4Expired = 0xA0,
    kTCReturnImage4UnknownFormat = 0xA1,
    kTCReturnImage4WrongObject = 0xA2,
    kTCReturnImage4WrongCrypto = 0xA3,
    kTCReturnImage4ManifestViolation = 0xA4,
    kTCReturnImage4PayloadViolation = 0xA5,
    kTCReturnImage4PermissionDenied = 0xA6,
    kTCReturnImage4NoChipAvailable = 0xA7,
    kTCReturnImage4NoNonceAvailable = 0xA8,
    kTCReturnImage4NoDeviceAvailable = 0xA9,
    kTCReturnImage4DecodeError = 0xAA,
    kTCReturnImage4UnknownError = 0xAF,

    /* Cannot exceed this value */
    kTCReturnTotal = 0xFF
};

typedef struct _TCReturn {
    union {
        /* Raw 32 bit representation of the return code */
        uint32_t rawValue;

        /* Formatted representation of the return code */
        struct {
            /* Component of the library which is returning the code */
            uint8_t component;

            /* Error code which is being returned */
            uint8_t error;

            /* Unique error path within the component */
            uint16_t uniqueError;
        } __attribute__((packed));
    } __attribute__((packed));
} __attribute__((packed)) TCReturn_t;

/* Ensure the size of the structure remains as expected */
_Static_assert(sizeof(TCReturn_t) == sizeof(uint32_t), "TCReturn_t is not 32 bits large");

static inline TCReturn_t
buildTCRet(uint8_t component,
           uint8_t error,
           uint16_t uniqueError)
{
    TCReturn_t ret = {
        .component = component,
        .error = error,
        .uniqueError = uniqueError
    };

    return ret;
}

__END_DECLS
#endif /* libTrustCache_Return_h */
