//
//  der_vm.h
//  CoreEntitlements
//

#pragma once

#include "CoreEntitlements.h"
#include <stdint.h>
#include <stdbool.h>

// The kernel doesn't have access to this one
#if __has_include (<corecrypto/ccder.h>)
#include <corecrypto/ccder.h>
#else
typedef unsigned long ccder_tag;
#endif


/*!
 * @typedef der_vm_context_t
 * Represents the current execution state of the DERQL interpreter.
 * The context can be initialized with der_vm_context_create  and subsequently used in invocations of der_vm_execute.
 * This object is passed by value and the functions that operate on the der_vm_context_t do not modify it but instead return a copy.
 * As a consequence, the state of the interpreter can be captured at any execution point by holding on to the context.
 */
typedef struct der_vm_context {
    CERuntime_t runtime;
    ccder_tag dictionary_tag;
    bool sorted;
    bool valid;
    struct {
        const uint8_t *der_start;
        const uint8_t *der_end;
    } state;
} der_vm_context_t;

/*!
 * @function der_vm_context_create
 * Returns an initialized, valid,  der_vm_context_t against which query operations may be performed
 * @param rt
 * Active runtime
 * @param dictionary_tag
 * Which DER tag should be used when matching dictionaries
 * @param sorted_keys
 * Whether the VM can assume that the keys are sorted
 * @param der
 * Pointer to the start of a DER object
 * @param der_end
 * Pointer to one byte past the end of the DER object
 * @discussion
 * The caller must ensure that the memory pointed to by der remains valid as long as the der_vm_context_t is used.
 * The caller must ensure that the DER object has been validated.
 */
der_vm_context_t der_vm_context_create(const CERuntime_t rt, ccder_tag dictionary_tag, bool sorted_keys, const uint8_t *der, const uint8_t *der_end);

/*!
 * @function der_vm_execute
 * Returns a new context that is derived by applying the op to the passed in context
 *
 * @param context
 * Context to execute against
 *
 * @param op
 * An operation to be performed against the context
 * This op should be created by one of the CEMatch* or CESelect* functions
 *
 * @discussion
 * If the VM encounters:
 *      1. Invalid operation
 *      2. An operation that fails to execute
 *      3. Invalid state
 * The VM will attempt to return an invalid context.
 * If the VM encounters an operation that it does not understand, the runtime's abort function will be executed.
 */
der_vm_context_t der_vm_execute(const der_vm_context_t context, CEQueryOperation_t op);

/*!
 * @typedef der_vm_iteration_context
 * Iteration context that gets passed in on every call
 *
 * @field original
 * The original DER VM context (the container over which we are iterating)
 *
 * @field active
 * The actively selected DER VM context (i.e. the value)
 *
 * @field parent_type
 * The type of object being iterated over (dictionary or array)
 *
 * @field active_type
 * The type of the selected object
 *
 * @field user_data
 * The object you passed in the call to der_vm_iterate
 */
typedef struct {
    der_vm_context_t original;
    der_vm_context_t active;
    CEType_t parent_type;
    CEType_t active_type;
    void* user_data;
} der_vm_iteration_context;

/*!
 * @typedef der_vm_iteration_callback
 *
 * @brief Function definition for the callback that der_vm_iterate uses
 *
 * @param ctx The information about the iterable is stored here
 */
typedef bool (*der_vm_iteration_callback)(der_vm_iteration_context ctx);

/*!
 * @function der_vm_iterate
 * @brief Iterates over a DER container, caliing the callback for every element
 *
 * @param context The context that points to a container
 * @param user_data This will be passed in verbatim in the der_vm_iteration_context
 * @param callback This function is called for every element
 *
 * @returns kCENoError if the function exited normally
 */
CEError_t der_vm_iterate(const der_vm_context_t context, void* user_data, der_vm_iteration_callback callback);

/*!
 * @function der_vm_context_is_valid
 * Returns a boolean indication if a particular context is valid
 *
 * @param context
 * The context in question
 *
 * @discussion
 * It is generally safe to execute any operation against an invalid context
 * However the resulting context will also be invalid
 */
bool der_vm_context_is_valid(const der_vm_context_t context);

/*!
 * @function der_vm_CEType_from_context
 * Returns a CEType_t corresponding to the context
 *
 * @param context
 * The context in question
 * @param tag
 * Nullable pointer to where to store the decoded DER tag
 */
CEType_t der_vm_CEType_from_context(const der_vm_context_t context, ccder_tag* tag);

/*!
 * @function der_vm_integer_from_context
 * Returns the number selected by the current context
 */
int64_t der_vm_integer_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_string_from_context
 * Returns the string selected by the current context
 */
CEBuffer der_vm_string_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_bool_from_context
 * Returns the bool selected by the current context
 */
bool der_vm_bool_from_context(const der_vm_context_t context);

/*!
 * @function der_vm_buffer_from_context
 * Returns the content described by the tag in the context
 */
CEBuffer der_vm_buffer_from_context(const der_vm_context_t context);
