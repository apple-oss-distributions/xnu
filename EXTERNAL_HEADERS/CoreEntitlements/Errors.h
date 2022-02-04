//
//  Errors.h
//  CoreEntitlements
//
//

#pragma once

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

/*!
 * @typedef CEError_t
 * A shared error type that is returned by CoreEntitlements APIs
 */
typedef const struct CEError * CEError_t;

// Macro to define the error for export;
#define CE_DEF_ERROR(name) extern CEError_t name;

// Returned on successful invocation
CE_DEF_ERROR(kCENoError);

// Returned when the library encounters API misuse
CE_DEF_ERROR(kCEAPIMisuse);

// Returned when an invalid argument has been passed in
CE_DEF_ERROR(kCEInvalidArgument);

// Returned when we expected to have allocated data, but we couldn't
CE_DEF_ERROR(kCEAllocationFailed);

// Returned when the passed in entitlements do not conform to any supported format
CE_DEF_ERROR(kCEMalformedEntitlements);

// Returned when a group of queries does not generate a valid result on the current CEQueryContext
CE_DEF_ERROR(kCEQueryCannotBeSatisfied);

/*!
 * @function CEGetErrorString
 * Returns a string that describes the error
 */
const char* CEGetErrorString(CEError_t error);
