//
//  QueryHelpers.h
//  CoreEntitlements
//

#pragma once

/*!
 * @function CEDynamic
 * Marks an opcode as being dynamic
 *
 * @param op
 * Opcode
 */
#define CEDynamic(op) (CEQueryOpOpcode_t)((op) | kCEOpDynamic)

/*!
 * @function CESelectIndex
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the entitlement object at the specified index
 *
 * @param index
 * The index of the object within a container
 *
 * @discussion
 * Using an index that is past the container's size will result in an invalid context
 */
#define CESelectIndex(index) (CEQueryOperation_t){.opcode = kCEOpSelectIndex, .parameters = {.numericParameter = index}}

/*!
 * @function CESelectKey
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the key of the dictionary pair
 * @discussion
 * Selecting a key on a non-dictionary-pair object is undefined behavior (i..e. it is implementation defined)
 */
#define CESelectKey() CESelectIndex(0)

/*!
 * @function CESelectValue
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the value of the dictionary pair
 * @discussion
 * Selecting a value on a non-dictionary-pair object is undefined behavior (i..e. it is implementation defined)
 */
#define CESelectValue() CESelectIndex(1)

/*!
 * @function CESelectDictValue
 * Returns an operation that when executed will modify the context such that any subsequent operation is performed on the object that corresponds
 * to the value pointed to by the specified key
 *
 * @param key
 * The key of the object within a container
 *
 * @discussion
 * Using a key that is not found in the container will result in an invalid context
 */
#define CESelectDictValue(key) (CEQueryOperation_t){.opcode = kCEOpSelectKey, .parameters = {.stringParameter = {.data = key, .length = sizeof(key) - 1}}}
#define CESelectDictValueDynamic(key, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpSelectKey), .parameters = {.dynamicParameter = {.data = key, .length = len}}}

/*!
 * @function CEMatchString
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid string and matches the string exactly
 *
 * @param string
 * The string to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchString(string) (CEQueryOperation_t){.opcode = kCEOpMatchString, .parameters = {.stringParameter = {.data = string, .length = sizeof(string) - 1}}}
#define CEMatchDynamicString(string, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpMatchString), .parameters = {.dynamicParameter = {.data = string, .length = len}}}

/*!
 * @function CEMatchPrefix
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid string and it's prefix matched the passed in prefix
 *
 * @param prefix
 * The prefix to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchPrefix(prefix) (CEQueryOperation_t){.opcode = kCEOpMatchStringPrefix, .parameters = {.stringParameter = {.data = prefix, .length = sizeof(prefix) - 1}}}
#define CEMatchDynamicPrefix(prefix, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpMatchStringPrefix), .parameters = {.dynamicParameter = {.data = prefix, .length = len}}}


/*!
 * @function CEMatchBool
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid boolean and matches the boolean exactly
 *
 * @param val
 * The bool to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchBool(val) (CEQueryOperation_t){.opcode = kCEOpMatchBool, .parameters = {.numericParameter = !!val}}

/*!
 * @function CEMatchInteger
 * Returns an operation that will return a valid context if and only if the context corresponds to a valid integer and matches the integer exactly
 *
 * @param val
 * The integer to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEMatchInteger(val) (CEQueryOperation_t){.opcode = kCEOpMatchInteger, .parameters = {.numericParameter = val}}

/*!
 * @function CEIsIntegerAllowed
 * Returns an operation that will return a valid context if 1) the current context is an integer and allows the integer, or 2) the context is an array of integers that allows the integer
 *
 * @param integer
 * The integer to match against
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsIntegerAllowed(integer) (CEQueryOperation_t){.opcode = kCEOpIntegerValueAllowed, .parameters = {.numericParameter = integer}}

/*!
 * @function CEIsStringAllowed
 * Returns an operation that will return a valid context if 1) the current context is a string and allows the string via wildcard rules, or 2) the context is an array of strings that allows the string
 *
 * @param string
 * The string to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsStringAllowed(string) (CEQueryOperation_t){.opcode = kCEOpStringValueAllowed, .parameters = {.stringParameter = {.data = string, .length = sizeof(string) - 1}}}
#define CEIsDynamicStringAllowed(string, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpStringValueAllowed), .parameters = {.dynamicParameter = {.data = string, .length = len}}}

/*!
 * @function CEIsStringPrefixAllowed
 * Returns an operation that will return a valid context if 1) the current context is a string and matches the prefix or 2) has an array that has the matches the prefix
 *
 * @param string
 * The string to match against (MUST BE A STRING LITERAL)
 *
 * @discussion
 * If a valid context is returned it will be in the same state as the execution context
 */
#define CEIsStringPrefixAllowed(string) (CEQueryOperation_t){.opcode = kCEOpStringPrefixValueAllowed, .parameters = {.stringParameter = {.data = string, .length = sizeof(string) - 1}}}
#define CEIsDynamicStringPrefixAllowed(string, len) (CEQueryOperation_t){.opcode = CEDynamic(kCEOpStringPrefixValueAllowed), .parameters = {.dynamicParameter = {.data = string, .length = len}}}

#pragma mark Helpers
/*
 Macro magic
 */
#define _SELECT_NTH_ARG(_1, _2, _3, _4, _5, _6, _7, _8, _9, N, ...) N

#define _mc_1(_call, x) _call(x),
#define _mc_2(_call, x, ...) _call(x), _mc_1(_call, __VA_ARGS__)
#define _mc_3(_call, x, ...) _call(x), _mc_2(_call, __VA_ARGS__)
#define _mc_4(_call, x, ...) _call(x), _mc_3(_call, __VA_ARGS__)
#define _mc_5(_call, x, ...) _call(x), _mc_4(_call, __VA_ARGS__)
#define _mc_6(_call, x, ...) _call(x), _mc_5(_call, __VA_ARGS__)
#define _mc_7(_call, x, ...) _call(x), _mc_6(_call, __VA_ARGS__)
#define _mc_8(_call, x, ...) _call(x), _mc_7(_call, __VA_ARGS__)
#define _mc_9(_call, x, ...) _call(x), _mc_8(_call, __VA_ARGS__)
#define _mc_10(_call, x, ...) _call(x), _mc_9(_call, __VA_ARGS__)

#define _MACRO_ITER(macro, ...) _SELECT_NTH_ARG(__VA_ARGS__, _mc_10, _mc_9, _mc_8 _mc_7, _mc_6, _mc_5, _mc_4, _mc_3, _mc_2, _mc_1)(macro, __VA_ARGS__)

/*!
 Macro to automatically generate a query path from a list of string sub components
 So
 @code
 CE_SELECT_PATH("hello, "world") will select a key "hello" and then look up "world" in the dictionary stored in the value of "hello"
 @endcode
 */
#define CE_SELECT_PATH(...) _MACRO_ITER(CESelectDictValue, __VA_ARGS__)

// Macro for string equals
#define CE_STRING_EQUALS(str) CEMatchString(str)

/*
 A macro that checks if the passed in context grants (via an explicit true boolean) the entitlement at the passed in path.
 */
#define CE_CONTEXT_GRANTS_ENTITLEMENT(ctx, ...) (CEContextQuery(ctx, (CEQuery_t){CE_SELECT_PATH(__VA_ARGS__) CEMatchBool(true)}, sizeof((CEQuery_t){CE_SELECT_PATH(__VA_ARGS__) CEMatchBool(true)}) / sizeof(CEQueryOperation_t)) == kCENoError)
