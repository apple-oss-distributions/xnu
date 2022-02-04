/*!
 * @header
 * Umbrella header for CoreEntitlements
 */
#pragma once

#ifdef __cplusplus
extern "C" {
#endif

typedef const struct CERuntime* CERuntime_t;
typedef struct CEQueryContext* CEQueryContext_t;

#define _CE_INDIRECT 1

#include <os/base.h>
#include "Errors.h"
#include "Result.h"
#include "Runtime.h"
#include "Entitlements.h"
#include "Serialization.h"

/*!
 * @typedef CEType_t
 * @brief Represents a type of element supported by CoreEntitlements
 *
 * @const kCETypeUnknown
 * An unknown type
 *
 * @const kCETypeDictionary
 * A dictionary container
 *
 * @const kCETypeSequence
 * An ordered sequence container
 *
 * @const kCETypeInteger
 * An integer.
 *
 * @const kCETypeString
 * A string of bytes.
 *
 * @const kCETypeBool
 * A boolean.
 */
OS_CLOSED_ENUM(CEType, uint32_t,
               kCETypeUnknown = 0,
               kCETypeDictionary = 1,
               kCETypeSequence = 2,
               kCETypeInteger = 3,
               kCETypeString = 4,
               kCETypeBool = 5);

/*!
 * @function CE_RT_LOG
 * Log a single message via the current runtime
 * Only called if the runtime supports logging.
 */
#define CE_RT_LOG(msg) do { if (rt->log) { rt->log(rt, "[%s]: %s\n", __FUNCTION__, msg); } } while(0)

/*!
 * @function CE_RT_LOGF
 * Logs using the passed in format. Printf like.
 * Only called if the runtime supports logging.
 */
#define CE_RT_LOGF(fmt, ...) do { if (rt->log) { rt->log(rt, "[%s]: " fmt, __FUNCTION__, __VA_ARGS__); } } while(0)

/*!
 * @function CE_RT_ABORT
 * Invokes the runtime abort function with a passed in message.
 * This function should not return.
 */
#define CE_RT_ABORT(...) do { rt->abort(rt, "[%s]: %s\n", __FUNCTION__, __VA_ARGS__); } while(0)

#ifdef __cplusplus
}
#endif
