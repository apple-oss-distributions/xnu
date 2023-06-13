//
//  Entitlements.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_ENTITLEMENTS_H
#define CORE_ENTITLEMENTS_ENTITLEMENTS_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <CoreEntitlements/Result.h>
#include <CoreEntitlements/Runtime.h>

__ptrcheck_abi_assume_single();

/*!
 * @enum CEVersion_t
 * Represents the various versions supported by CoreEntitlements
 */
OS_ENUM(CEVersion, int64_t,
        kCEVersionInvalid = 0,
        kCEVersionZero = 1,
        kCEVersionOne = 2);

/*!
 * @struct CEValidationResult
 * Contains the result of the call to CEValidate
 */
typedef struct {
    CEVersion_t version;
    const uint8_t *__ended_by(blob_end) blob;
    const uint8_t * blob_end;
} CEValidationResult;

typedef struct {
    bool allow_data_elements;
} CEValidationOptions;

/*!
 * @function CEValidate
 * Validates if the provided blob conforms to one of the entitlement specification understood by CoreEntitlements
 * @param rt
 * Active runtime
 * @param result
 * The validation result will be stored here
 * @param blob
 * Pointer to the start of the entitlements object
 * @param blob_end
 * Pointer to one byte past the end of the entitlements object
 * @discussion
 * This function will return kCENoError if the entitlements are valid
 */
CEError_t CEValidate(const CERuntime_t rt, CEValidationResult* result, const uint8_t *__ended_by(blob_end) blob, const uint8_t* blob_end) __result_use_check;
/*!
 * @function CEValidateWithOptions
 * Validates if the provided blob conforms to one of the entitlement specification understood by CoreEntitlements
 * @param rt
 * Active runtime
 * @param options
 * Options that modify how validation behaves
 * @param result
 * The validation result will be stored here
 * @param blob
 * Pointer to the start of the entitlements object
 * @param blob_end
 * Pointer to one byte past the end of the entitlements object
 * @discussion
 * This function will return kCENoError if the entitlements are valid
 */
CEError_t CEValidateWithOptions(const CERuntime_t rt, CEValidationOptions* options, CEValidationResult* result, const uint8_t *__ended_by(blob_end) blob, const uint8_t* blob_end) __result_use_check;

/*!
 * @function CEAcquireManagedContext
 * Creates and returns a managed query context for the validated blob against which you can perform queries
 * @param rt
 * Active runtime (must support allocation and deallocation)
 * @param validationResult
 * The validation result returned by  CEValidate
 * @param ctx
 * Pointer to where the context is to be returned
 * @note
 * The returned managed context must be subsequently released with CEAcquireManagedContext
 */
CEError_t CEAcquireManagedContext(const CERuntime_t rt, CEValidationResult validationResult, CEQueryContext_t* ctx) __result_use_check;

/*!
 @discussion
 Releases the managed context
 */
CEError_t CEReleaseManagedContext(CEQueryContext_t* ctx);

/*!
 * @enum CEQueryOpOpcode_t
 * These are all the supported operations by the CoreEntitlements VM
 */
OS_ENUM(CEQueryOpOpcode, int64_t,
        kCEOpNoop = 0,
        kCEOpSelectKey = 1,
        kCEOpSelectIndex = 2,
        kCEOpMatchString = 3,
        kCEOpMatchStringPrefix = 4,
        kCEOpMatchBool = 5,
        kCEOpStringValueAllowed = 6,
        kCEOpMatchInteger = 7,
        kCEOpStringPrefixValueAllowed = 8,
        kCEOpSelectKeyWithPrefix = 9,
        kCEOpIntegerValueAllowed = 10,
        kCEOpMatchType = 11,
        kCEOpMatchData = 12,
        kCEOpMatchDataValueAllowed = 13,
        kCEOpMaxOperation = 14, /* Sentinel value */
        kCEOpDynamic = 0x1LL << 62);



/*!
 * @typedef CEQueryOperation_t
 * Represents an operation within the DERQL interpreter
 * The opcode specified _which_ operation to perform, while the parameters specify how to perform it.
 * Operations are passed by value and may be safely reused.
 */
typedef struct CEQueryOperation {
    CEQueryOpOpcode_t opcode;
    union {
        CEBuffer dynamicParameter;
        CEStaticBuffer stringParameter;
        int64_t numericParameter;
    } parameters;
} CEQueryOperation_t;

typedef CEQueryOperation_t CEQuery_t[];

extern const CEQueryOperation_t* CESelectKeyOperation;
extern const CEQueryOperation_t* CESelectValueOperation;

/*!
 * @typedef CEPrepareOptions_t
 * Containts the options you may pass in to CEPrepareQuery.
 */
typedef struct CEPrepareOptions {
    /*
     If materialize is true dynamic ops are turned into static ones
     */
    bool materialize;
    /*
     Controls if CEPrepareQuery should fail on keys in dynamic operations that are too long
     */
    bool failOnOversizedParameters;
} CEPrepareOptions_t;

/*!
 * @function CEContextQuery
 * Performs a query on the passed in CEQueryContext_t
 *
 * @param ctx
 * The context on which to perform the query
 *
 * @param query
 * The sequence of operations to execute
 *
 * @param queryLength
 * The number of operations in the query
 *
 * @returns
 * This function will return kCENoError if the query is satisfiable, otherwise kCEQueryCannotBeSatisfied.
 *
 * @note
 * As stated previously, the query only succeeds if it is satisfiable by the context, meaning that the operations executed in the passed in order
 * leave the VM in the valid state. An invalid state may arise from a variety of situations, like trying to select a value for a key that doesn't exist,
 * or a failing string matching operations.
 */
CEError_t CEContextQuery(CEQueryContext_t ctx, const CEQueryOperation_t *__counted_by(queryLength) query, size_t queryLength) __result_use_check;

/*!
 * @function CEPrepareQuery
 * Prepares the query for execution by materializing dynamic operations if needed
 * 
 * @params options
 * Options to control how the query should be prepared
 *
 * @param query
 * The sequence of operations to prepare
 *
 * @param queryLength
 * The number of operations in the query
 */
CEError_t CEPrepareQuery(CEPrepareOptions_t options, CEQueryOperation_t *__counted_by(queryLength) query, size_t queryLength);

/*!
 * @function CEContextIsSubset
 * Checks if the subset <-> superset relation holds between two context.
 * The logic relations used to establish that relation correspond to the normal profile-validation rules.
 *
 * @param subset
 * The context that is meant to a subset
 *
 * @param superset
 * The context that is meant to be a superset
 *
 * @returns
 * This function will return kCENoError if the relation holds, otherwise kCEQueryCannotBeSatisfied.
 */
CEError_t CEContextIsSubset(CEQueryContext_t subset, CEQueryContext_t superset);

#include <CoreEntitlements/QueryHelpers.h>

#endif
