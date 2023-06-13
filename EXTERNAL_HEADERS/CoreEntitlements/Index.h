//
//  Index.h
//  CoreEntitlements
//
//

#ifndef CORE_ENTITLEMENTS_INDEX_H
#define CORE_ENTITLEMENTS_INDEX_H

#ifndef _CE_INDIRECT
#error "Please include <CoreEntitlements/CoreEntitlements.h> instead of this file"
#endif

#include <CoreEntitlements/Result.h>

/*
 The kernel always supports acceleration
 */
#define CE_ACCELERATION_SUPPORTED 1


/*!
 @typedef CEAccelerationElement_t
 
 A single element of the acceleration structure, the contents of this struct are an implementation detail
 and are subject to change.
 */
typedef struct CEAccelerationElement {
    uint32_t key_offset;
    uint32_t key_length;
} CEAccelerationElement_t;

/*!
 @struct CEAccelerationContext
 
 Contains data required to accelerate queries, the contents of this struct are an implementation detail
 and are subject to change.
 */
struct CEAccelerationContext {
    CEAccelerationElement_t * __counted_by(index_count) index;
    size_t index_count;
};

/*!
 @function CEIndexSizeForContext
 Computes an upper bound of memory needed to construct an acceleration index for a particular query context.
 
 @param context
 The context for which the calculation should be made
 
 @param size
 Contains the required size, in bytes.
 
 @returns an error if the context cannot be accelerated, success otherwise
 */
CEError_t CEIndexSizeForContext(CEQueryContext_t context, size_t* size);

/*!
 @function CEBuildIndexForContext
 Computes and stores and acceleration index into the passed in context.
 Building an index requires runtime support.
 
 @param context
 The context for which the index should be computed.
 */
CEError_t CEBuildIndexForContext(CEQueryContext_t context);

/*!
 @function CEFreeIndexForContext
 Frees an index associated with a query context
 
 @param context
 The context for which the index should be freed.
 */
CEError_t CEFreeIndexForContext(CEQueryContext_t context);

/*!
 @function CEContextIsAccelerated
 Checks if the passed in context supports query acceleration
 
 @param context
 The context to check.
 */
bool CEContextIsAccelerated(CEQueryContext_t context);

#endif /* CORE_ENTITLEMENTS_INDEX_H */
