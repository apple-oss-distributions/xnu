//
//  Serialization.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_SERIALIZATION_H
#define CORE_ENTITLEMENTS_SERIALIZATION_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <CoreEntitlements/Result.h>
#include <CoreEntitlements/Runtime.h>
#include <CoreEntitlements/Entitlements.h>

__ptrcheck_abi_assume_single();

/*!
 * @enum CESerializedElementType_t
 * These are the primitive types that CoreEntitlements can serialize
 * Depending on the underlying representation some of these elements may be "virtual" or zero-sized.
 * However, they must still be included.
 */
OS_CLOSED_ENUM(CESerializedElementType, int64_t,
               /* A boolean element with a true / false value */
               kCESerializedBool = 1,
               /* A string element with a definite length */
               kCESerializedString = 2,
               /* A key string element with a definite length */
               kCESerializedKey = 3,
               /* An integer element, must be representable as int64_t */
               kCESerializedInteger = 4,
               /* Marks the start of an array / ordered sequence */
               kCESerializedArrayBegin = 5,
               /* Marks the end of an array / ordered sequence */
               kCESerializedArrayEnd = 6,
               /* Marks the start of a dictionary */
               /* The only valid elements contained in a dictionary are tuples (represented as an ordered sequence) */
               /* The first element of the ordered sequence must be kCESerializedString value */
               /* No restrictions are placed on the contents of the second element*/
               kCESerializedDictionaryBegin = 7,
               /* Marks the end of a dictionary */
               kCESerializedDictionaryEnd = 8,
               /* A data element with a definite length*/
               kCESerializedData = 9,
               );

/*!
 * @typedef CESerializedElement_t
 * This structure represents an encodable piece of data, along with its type and length (in bytes).
 * For the most part you will not need to use this structure manually, and instead you should use the helpers below
 */
typedef struct CESerializedElement {
    CESerializedElementType_t type;
    union {
#if !__has_ptrcheck
        void* bytes;
#endif
        int64_t value;
    } data;
    size_t length;
    bool pair;
} CESerializedElement_t;

static inline void *CE_HEADER_INDEXABLE CESerializedElementGetData(const CESerializedElement_t *element) {
    return __unsafe_forge_bidi_indexable(void *, element->data.value, element->length);
}

static inline void CESerializedElementSetData(CESerializedElement_t *element, void *__sized_by(length) bytes, size_t length) {
    element->data.value = (intptr_t)bytes;
    element->length = length;
}

/*!
 * @function CESizeSerialization
 * This function will iterate over the elements that are to be serialized and compute the size of an allocation that needs to be made
 * for a successful serialization.
 *
 * @note
 * This function may modify the length field of the CESerializedElements that are passed in. This must be done for serialization to succeed
 *
 * @returns
 * kCENoError if the requiredSize has been successfully populated and contains a valid value
 */
CEError_t CESizeSerialization(CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, size_t* requiredSize) __result_use_check;

/*!
 * @function CESizeXMLSerialization
 * This function will iterate over the elements that are to be serialized and compute the size of an allocation that needs to be made
 * for a successful serialization to XML.
 *
 * @note
 * This function may modify the length field of the CESerializedElements that are passed in. This must be done for serialization to succeed
 *
 * @returns
 * kCENoError if the requiredSize has been successfully populated and contains a valid value
 */
CEError_t CESizeXMLSerialization(CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, size_t* requiredSize) __result_use_check;

/*!
 * @function CESerializeWithOptions
 * Serializes the array of elements that contains the underlying data. The elements must have been sized with CESizeSerialization before calling this function.
 *
 * @param runtime
 * The runtime to use for this operation
 *
 * @param options
 * Options that modify what can be serialized.
 *
 * @param elements
 * The list of elements to serialize
 *
 * @param elementsCount
 * How many elements are in that list
 *
 * @param start
 * A pointer to the first byte into a buffer that will be filled with the serialized representation
 *
 * @param end
 * A pointer 1 byte past the end of the buffer to be used for serialization
 */
CEError_t CESerializeWithOptions(const CERuntime_t runtime, CEValidationOptions* options, CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, uint8_t *__ended_by(end) start, uint8_t* end) __result_use_check;

/*!
 * @function CESerialize
 * Serializes the array of elements that contains the underlying data. The elements must have been sized with CESizeSerialization before calling this function.
 *
 * @param runtime
 * The runtime to use for this operation
 *
 * @param elements
 * The list of elements to serialize
 *
 * @param elementsCount
 * How many elements are in that list
 *
 * @param start
 * A pointer to the first byte into a buffer that will be filled with the serialized representation
 *
 * @param end
 * A pointer 1 byte past the end of the buffer to be used for serialization
 */
CEError_t CESerialize(const CERuntime_t runtime, CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, uint8_t *__ended_by(end) start, uint8_t* end) __result_use_check;

/*!
 * @function CESerializeXML
 * Serializes the array of elements that contains the underlying data. The elements must have been sized with CESizeXMLSerialization before calling this function.
 *
 * @param runtime
 * The runtime to use for this operation
 *
 * @param elements
 * The list of elements to serialize
 *
 * @param elementsCount
 * How many elements are in that list
 *
 * @param start
 * A pointer to the first byte into a buffer that will be filled with the serialized representation
 *
 * @param end
 * A pointer 1 byte past the end of the buffer to be used for serialization
 */
CEError_t CESerializeXML(const CERuntime_t runtime, CESerializedElement_t elements[__counted_by(elementsCount)], size_t elementsCount, uint8_t *__ended_by(end) start, uint8_t* end) __result_use_check;

// Helpers
// These automatically construct CESerializedElements for you
#define CESerializeInteger(intv) (CESerializedElement_t){.type = kCESerializedInteger, .data.value = intv}
#define CESerializeBool(boolVal) (CESerializedElement_t){.type = kCESerializedBool, .data.value = !!boolVal}
#define CESerializeStaticString(strVal) (CESerializedElement_t){.type = kCESerializedString, .data.value = (intptr_t)strVal, .length = sizeof(strVal) - 1}
#define CESerializeKey(strVal) (CESerializedElement_t){.type = kCESerializedKey, .data.value = (intptr_t)strVal, .length = sizeof(strVal) - 1}
#define CESerializeDynamicKey(strVal, len) (CESerializedElement_t){.type = kCESerializedKey, .data.value = (intptr_t)strVal, .length = len}
#define CESerializeString(strVal, len) (CESerializedElement_t){.type = kCESerializedString, .data.value = (intptr_t)strVal, .length = len}
#define CESerializeData(dataVal, len) (CESerializedElement_t){.type = kCESerializedData, .data.value = (intptr_t)dataVal, .length = len}
#define CESerializeArray(...) (CESerializedElement_t){.type = kCESerializedArrayBegin}, __VA_ARGS__ , (CESerializedElement_t){.type = kCESerializedArrayEnd}
#define CESerializeDictionary(...) (CESerializedElement_t){.type = kCESerializedDictionaryBegin}, __VA_ARGS__ , (CESerializedElement_t){.type = kCESerializedDictionaryEnd}
#define CESerializeDictionaryPair(a, b) CESerializeArray(a, b)

#endif
