//
//  Result.h
//  CoreEntitlements
//

#ifndef CORE_ENTITLEMENTS_RESULT_H
#define CORE_ENTITLEMENTS_RESULT_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <sys/cdefs.h>
__ptrcheck_abi_assume_single();

#include <CoreEntitlements/Errors.h>
#include <stdint.h>

/*!
 * @function CEErrorPassThrough
 * Returns its argument. Convenient breakpoint location for when anything raises an error.
 */
static inline CEError_t CEErrorPassThrough(CEError_t E) {
    return E;
}

/*!
 * @function CE_CHECK
 * Checks if the passed in return value from one of CoreEntitlements function is an error, and if so returns that error in the current function
 */
#define CE_CHECK(ret) do { CEError_t _ce_error = ret; if (_ce_error != kCENoError) {return CEErrorPassThrough(_ce_error);} } while(0)

/*!
 * @function CE_THROW
 * Macro to "throw" (return) one of the CEErrors
 */
#define CE_THROW(err) return CEErrorPassThrough(err)

/*!
 * @function CE_OK
 * Returns a true if the passed in value corresponds to kCENoError
 */
#define CE_OK(ret) ((ret) == kCENoError)

#endif
