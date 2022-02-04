//
//  Result.h
//  CoreEntitlements
//

#pragma once

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include "Errors.h"
#include <stdint.h>

/*!
 * @function CE_CHECK
 * Checks if the passed in return value from one of CoreEntitlements function is an error, and if so returns that error in the current function
 */
#define CE_CHECK(ret) do { CEError_t _ce_error = ret; if (_ce_error != kCENoError) {return _ce_error;} } while(0)

/*!
 * @function CE_THROW
 * Macro to "throw" (return) one of the CEErrors
 */
#define CE_THROW(err) return err

/*!
 * @function CE_OK
 * Returns a true if the passed in value corresponds to kCENoError
 */
#define CE_OK(ret) ((ret) == kCENoError)
