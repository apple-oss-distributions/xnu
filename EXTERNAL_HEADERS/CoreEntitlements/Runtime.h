//
//  Runtime.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_RUNTIME_H
#define CORE_ENTITLEMENTS_RUNTIME_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

__ptrcheck_abi_assume_single();

#define CE_MAX_KEY_SIZE 240

#ifndef __result_use_check
#define __result_use_check
#endif

#define CE_RUNTIME_VERSION 1
#define CE_RUNTIME_WITH_INDEX_VERSION 2

/*!
 * @struct CEBuffer
 * Represents a sized chunk of DER data
 * Strings and blobs used and returned by CoreEntitlements always use CEBuffer
 *
 * @note
 * If a DER string is returned to you via a CEBuffer, you cannot assume it is null-terminated.
 */
typedef struct {
    const uint8_t *__counted_by(length) data;
    size_t length;
} CEBuffer;

/*!
 * @struct CEStaticBuffer
 * Represents a sized chunk of data that is stored inline
 */
typedef struct {
    uint8_t data[CE_MAX_KEY_SIZE];
    size_t length;
} CEStaticBuffer;

#define CEBuffStr(str) (CEBuffer){.data = (const uint8_t*)str, .length = sizeof(str) - 1}

/*!
 * @typedef CERuntimeMalloc
 * Function prototype that the CERuntime may ues to allocate data (e.g.. malloc)
 */
typedef void* __unsafe_indexable (*CERuntimeMalloc)(const CERuntime_t rt, size_t size) __result_use_check;
/*!
 * @typedef CERuntimeFree
 * Function prototype that the CERuntime may ues to free allocated data (e.g. free)
 */
typedef void (*CERuntimeFree)(const CERuntime_t rt, void* address);
/*!
 * @typedef CERuntimeLog
 * Function prototype that the CERuntime may use to log helpful information (e.g. printf)
 */
typedef void (*CERuntimeLog)(const CERuntime_t rt, const char* __unsafe_indexable fmt, ...) __printflike(2, 3);
/*!
 * @typedef CERuntimeAbort
 * Function prototype that the CERuntime will use if it encounters a condition which may compromise the integrity of the system (e.g. abort, panic)
 */
typedef void (*CERuntimeAbort)(const CERuntime_t rt, const char* __unsafe_indexable fmt, ...) __printflike(2, 3) __attribute__((noreturn));
/*!
 * @typedef CERuntimeInternalStatus
 * Function prototype that the CERuntime may use to query AppleInternal status
 */
typedef bool (*CERuntimeInternalStatus)(const CERuntime_t rt);

/*!
 * @typedef CERuntimeAllocIndex
 * Function prototype that the CERuntime may ues to allocate an index of the specified size
 */
typedef void* __unsafe_indexable (*CERuntimeAllocIndex)(const CERuntime_t rt, size_t size) __result_use_check;

/*!
 * @typedef CERuntimeFreeIndex
 * Function prototype that the CERuntime may ues to free an index of the specified size
 */
typedef void (*CERuntimeFreeIndex)(const CERuntime_t rt, void* index, size_t size);

/*!
 * @struct CERuntime
 * This structure represents the interface that CoreEntitlements uses to communicate with the outside world.
 * The presense or absence of function pointers in this structure may degrade certain functionality.
 *
 * @note
 * The only prototype that MUST be implemented is CERuntimeAbort abort.
 */
struct CERuntime {
    const uint64_t                  version;
    const CERuntimeMalloc           alloc;
    const CERuntimeFree             free;
    const CERuntimeLog              log;
    const CERuntimeAbort            abort;
    const CERuntimeInternalStatus   internalStatus;
    const CERuntimeAllocIndex       allocIndex;
    const CERuntimeFreeIndex        freeIndex;
} ;

#endif
