/*
 * Copyright (c) 2000-2025 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#pragma once

#include "mocks/std_safe.h"
#include "mocks/osfmk/unit_test_utils.h"
#include <dyld-interposing.h>

/* BEGIN IGNORE CODESTYLE */
__BEGIN_DECLS

/* Dynamic mock allows an individual test executable to control what a mock that is defined
 * in libmocks.dylib does.
 * T_MOCK_DECLARE(ret, name, args_def)
 *   Declare a dynamic mock. This declaration should come in a header file under the mocks/ folder.
 *   The header file should be included in both the respective .c file of the same name and in the
 *   test .c file that wants to set the behaviour of the mock.
 *   It declares the signature of the mocked function so that if the signature changes, the compiler
 *   can assure that the mock and its setters are in sync.
 * T_MOCK_F(ret, name, args_def, args_invoke) { default_action }
 *   Define the dynamic mock with a default action. This should come in a .c file under the mocks/ folder.
 *   An invocation of this macro should be immediately followed by the body of the default action
 * T_MOCK(ret, name, args_def, args_invoke)
 *   Define a dynamic mock where the default action calls the original function.
 *
 * @argument ret is the type of the return value of the function.
 * @argument name is the name of the function from XNU to mock.
 * @argument args_def is how the function arguments are defined in the function definition.
 *           This can be copy-pasted directly from the original function definition.
 * @argument args_invoke is how the same arguments are passed to a function call
 * @argument default_action should be a scope of code that will be executed if no mock control
 *           is set up in a test. It can reference the arguments in args_def and also call the original
 *           function. If this argument is not supplied, the default action is to call the original XNU
 *           function with the same arguments.
 *
 * The test has 4 possible way to control the mock. It can temporarily set the return value,
 * it can set a temporary block callback, it can set a permanent return value that will be in effect
 * for all the tests in a .c file, or a permanent function.
 *
 * Example:
 * // we want to mock a function from XNU that has the signature:
 * size_t foobar(int a, char b);
 *
 * // in a header in the mocks folder (tests/unit/mocks) add:
 * T_MOCK_DECLARE(size_t, foobar, (int a, char b));
 *
 * // in a .c file in the mock folder (tests/unit/mocks) add:
 * T_MOCK(size_t, foobar, (int a, char b), (a, b));
 *
 * // Now to control the mock, in a T_DECL test you can do:
 * T_DECL(test, "test") {
 *     // first option, constant ret val for this scope
 *     T_MOCK_SET_RETVAL(foobar, size_t, 42);
 *     // ... call into XNU which will call foobar()
 *
 *     // second option, callback for this scope
 *     T_MOCK_SET_CALLBACK(foobar, size_t, (int a, char b), {
 *         T_ASSERT_EQ(a, b, "args equal");
 *         return a + b;
 *     });
 *     // ... call into XNU which will call foobar()
 * }
 *
 * // The third option is to define a permanent return value for the mock that will
 * // be in effect for all tests in the executable.
 * // This essentially overrides the default-value that's defined in the T_MOCK()
 * T_MOCK_SET_PERM_RETVAL(foobar, size_t, 43);
 *
 * // The fourth option is for the test to define a permanent function in the global scope
 * // that will be called every time the mock is called.
 * T_MOCK_SET_PERM_FUNC(size_t, foobar, (int a, char b)) {
 *     return b - a;
 * }
 *
 * It's possible for multiple mock controls of different types to be active at the same time. The priority
 * in which the dynamic mock tries to find them is
 *   1. scoped ret-val
 *   2. scoped block call back
 *   3. permanent ret-val / permanent function
 * The effect of the scoped ret-val and scoped callback setters is limited to the scope the they are in. This
 * is achieved using a cleanup function in the setter.
 * It is possible for multiple setters of the same type to be invoked during the flow of the same scope.
 * In that case, the last setter that was invoked is in effect.
 *
 * It is not possible to have multiple static function setters and/or permanent ret-val setter for the
 * same mock in the same test executable. This would cause a compile/link error due to duplicate symbol.
 */

#define _T_MOCK_RETVAL_CALLBACK(name)       _mock_retval_callback_ ## name
#define _T_MOCK_CALLBACK(name)              _mock_callback_ ## name
#define _T_MOCK_PERM_RETVAL_FUNC(name)      _mock_p_retval_func_ ## name
#define _T_MOCK_PERM_FUNC(name)             _mock_func_ ## name
#define _T_MOCK_ENTRY(name)                 _mock_entry_ ## name
#define _T_MOCK_ENTRY_REG(name)             _mock_entry_reg_ ## name
#define T_MOCK_DEFAULT_ACTION(name)         _mock_default_ ## name
#define T_MOCK_ORIGINAL(name)               ORIGINAL_ ## name
#define T_MOCK_MOCK(name)                   MOCK_ ## name

/*
 * The mocks definitions construct a linked list of structs with information about the mocks
 * This is used by mocks_test to verify at runtime the correctness of the mocks.
 */
struct mock_entry {
    const char* me_name;
    void* me_original_func;
    void* me_mock_func;
    const char* me_location;
    struct mock_entry* me_next;
};
extern void _mock_entry_register(struct mock_entry *entry);
extern struct mock_entry* _mock_entry_first(void);
// print to the console all the mocks registered
extern void ut_print_all_mocks(void);

/*
 * _T_MOCK_INTERNAL() is used for replacing a function from XNU with a fixed implementation.
 * This is an internal facility and should not be used directly for defining mocks. Use T_MOCK() instead
 * - declare both the original function and the mock function so it can be use by the interpose macro
 * - interpose one for the other
 * - define the signature of the mock functions, the mock function body needs to follow
 *
 * Code that is compiled to libmocks.dylib can call the original function directly since
 * If the test want to call the original function it needs to use T_MOCK_ORIGINAL()
 */
#define _T_MOCK_INTERNAL(ret, name, args_def)       \
	extern ret name args_def;                       \
    ret T_MOCK_MOCK(name) args_def;                 \
    ret (*T_MOCK_ORIGINAL(name)) args_def = name;   \
    DYLD_INTERPOSE(T_MOCK_MOCK(name), name)         \
    ret T_MOCK_MOCK(name) args_def

#define T_MOCK_DECLARE(ret, name, args_def)               \
    extern ret (^_T_MOCK_RETVAL_CALLBACK(name))(void);    \
    extern ret (^_T_MOCK_CALLBACK(name)) args_def;        \
    extern ret (*_T_MOCK_PERM_RETVAL_FUNC(name))(void);   \
    extern ret (*_T_MOCK_PERM_FUNC(name)) args_def;       \
    extern ret T_MOCK_DEFAULT_ACTION(name) args_def;      \
    extern ret (*T_MOCK_ORIGINAL(name)) args_def;         \
    extern ret T_MOCK_MOCK(name) args_def;                \
    extern ret name args_def

#define __STRINGIFY(x) #x
#define __STRINGIFY2(x) __STRINGIFY(x)

/* T_MOCK_F() defines the different kinds of callbacks and the static body
 * of the mock that calls one of them
 * Usage of this should be immediately followed by the body of the default action.
 */
#define T_MOCK_F(ret, name, args_def, args_invoke)                        \
    ret (^_T_MOCK_RETVAL_CALLBACK(name)) (void) = NULL;                   \
    ret (^_T_MOCK_CALLBACK(name)) args_def = NULL;                        \
    ret (*_T_MOCK_PERM_RETVAL_FUNC(name)) (void) = NULL;                  \
    ret (*_T_MOCK_PERM_FUNC(name)) args_def = NULL;                       \
    ret T_MOCK_DEFAULT_ACTION(name) args_def;                             \
    _T_MOCK_INTERNAL(ret, name, args_def) {                               \
        if (_T_MOCK_RETVAL_CALLBACK(name) != NULL) {                      \
            return _T_MOCK_RETVAL_CALLBACK(name)();                       \
        }                                                                 \
        if (_T_MOCK_CALLBACK(name) != NULL) {                             \
            return _T_MOCK_CALLBACK(name) args_invoke;                    \
        }                                                                 \
        if (_T_MOCK_PERM_RETVAL_FUNC(name) != NULL) {                     \
            return _T_MOCK_PERM_RETVAL_FUNC(name)();                      \
        }                                                                 \
        if (_T_MOCK_PERM_FUNC(name) != NULL) {                            \
            return _T_MOCK_PERM_FUNC(name) args_invoke;                   \
        }                                                                 \
        return T_MOCK_DEFAULT_ACTION(name) args_invoke;                   \
    }                                                                     \
    static struct mock_entry _T_MOCK_ENTRY(name) = { .me_name = #name,    \
        .me_original_func = (void*)name,                                  \
        .me_mock_func = (void*)T_MOCK_MOCK(name),                         \
        .me_next = NULL,                                                  \
        .me_location = __FILE_NAME__ ":" __STRINGIFY2(__LINE__)           \
    };                                                                    \
    __attribute__((constructor)) static void _T_MOCK_ENTRY_REG(name)() {  \
        _mock_entry_register(&_T_MOCK_ENTRY(name));                       \
    }                                                                     \
    ret T_MOCK_DEFAULT_ACTION(name) args_def


#define T_MOCK(ret, name, args_def, args_invoke) \
    T_MOCK_F(ret, name, args_def, args_invoke) { return name args_invoke; }

#define _UT_CONCAT2(a, b) a ## b
#define _UT_CONCAT(a, b) _UT_CONCAT2(a, b)

struct _mock_setter_args {
        void **target;
        void *value;
};

static inline void
_mock_setter(struct _mock_setter_args *args) {
        *args->target = args->value;
}

/* How it works?
 * - For each mock that is defined using T_MOCK() the macro above defines a few
 * global variables with the function name suffixed, and also defines the mock function to check
 * these global variables.
 * - The test executable can then set any of them using the T_MOCK_SET_X() macros below
 * - T_MOCK_SET_RETVAL() and T_MOCK_SET_CALLBACK() should be used from inside T_DECL and have a
 * cleaner that undoes their effect at the end of the scope they are defined in.
 * The cleaner has a __COUNTER__ concatenated so that it's possible to have more than one such
 * T_MOCK_SET_X() invocation in the same scope
 * - T_MOCK_SET_PERM_RETVAL() and T_MOCK_SET_PERM_FUNC() should be used in the global scope
 * and has a constructor function that sets the global variable when the executable loads
 */

#define _T_MOCK_CLEANER(name) _UT_CONCAT(_cleaner_ ## name, __COUNTER__)
#define _T_MOCK_RETVAL_CAPTURE(name, N) _UT_CONCAT(_mock_retval_capture_ ## name, N)

/* to set a return value, we set a global that holds a callback block that returns the value.
 * The callback variable is a pointer and NULL indicates it's not set
 * The value expression the user gives is first captured in a local variable since some
 * expressions can't be captured by a block (array reference for instance) */
#define _T_MOCK_SET_RETVAL_IMPL(name, ret, val, N)                                              \
        ret _T_MOCK_RETVAL_CAPTURE(name, N) = val;                                              \
        _T_MOCK_RETVAL_CALLBACK(name) = ^ret(void) { return _T_MOCK_RETVAL_CAPTURE(name, N); }; \
        __attribute__((cleanup(_mock_setter))) struct _mock_setter_args _T_MOCK_CLEANER(name) = \
        { .target = (void**)&_T_MOCK_RETVAL_CALLBACK(name), .value = NULL };

#define T_MOCK_SET_RETVAL(name, ret, val) _T_MOCK_SET_RETVAL_IMPL(name, ret, val, __COUNTER__)

/* to set a mock callback block from the user we set a dedicated callback for that, so it doesn't
 * interfere with SET_RETVAL */
#define T_MOCK_SET_CALLBACK(name, ret, args_def, body)                                          \
        __attribute__((cleanup(_mock_setter))) struct _mock_setter_args _T_MOCK_CLEANER(name) = \
        { .target = (void**)&_T_MOCK_CALLBACK(name), .value = NULL };                           \
        _T_MOCK_CALLBACK(name) = ^ret args_def body;

/* temporarily remove the callback so that you can call into the default mock implementation */
#define T_MOCK_REMOVE_CALLBACK(name)                                          \
        __attribute__((cleanup(_mock_setter))) struct _mock_setter_args _T_MOCK_CLEANER(name) = \
        { .target = (void**)&_T_MOCK_CALLBACK(name),                                            \
          .value = _T_MOCK_CALLBACK(name) };                                                    \
        _T_MOCK_CALLBACK(name) = NULL;

#define T_MOCK_CALL_ORIGINAL(name, ...) \
  ({                                    \
      T_MOCK_REMOVE_CALLBACK(name);     \
      name(__VA_ARGS__);                \
  })

#define _T_MOCK_CTOR_SETTER(name) _ctor_setter_ ## name
#define _T_MOCK_PERM_HOOK(name)   PERM_HOOK_ ## name

/* To set a permanent return value, we define a function that returns it, and set it to the
 * extern global in a constructor.
 * This setter needs to be in the global scope of the tester */
#define T_MOCK_SET_PERM_RETVAL(name, ret, val)                          \
        ret _T_MOCK_PERM_HOOK(name)(void) { return (val); }             \
        __attribute__((constructor)) void _T_MOCK_CTOR_SETTER(name)() { \
            _T_MOCK_PERM_RETVAL_FUNC(name) = _T_MOCK_PERM_HOOK(name);   \
        }

/* To set a permanent function that will be called from the mock we declare it, set it to the extern
 * in a constructor and define it.
 * This needs to be in the global scope and the body of the function needs to follows it immediately */
#define T_MOCK_SET_PERM_FUNC(ret, name, args_def)                        \
        ret _T_MOCK_PERM_HOOK(name) args_def;                            \
        __attribute__((constructor)) void _T_MOCK_CTOR_SETTER(name)() {  \
            _T_MOCK_PERM_FUNC(name) = _T_MOCK_PERM_HOOK(name);           \
        }                                                                \
        ret _T_MOCK_PERM_HOOK(name) args_def


/* T_MOCK_CALL_QUEUE()
 *   Allow tests to define a call expectation queue for a mock
 *
 * This macro wraps a definition of a struct and defines easy helpers to
 * manage a global queue of elements of that struct.
 * A test can use this along with a mock callback to verify and control what the mock
 * does in every call it gets.
 * @argument type_name the name of the struct to define
 * @argument struct_body the elements of the struct
 *
 * Example:
 * // for mocking the function foobar() we'll define a struct that will allow the mock
 * // to verify its arguments and control its return value. The elements of the struct can
 * // be anything.
 * T_MOCK_CALL_QUEUE(fb_call, {
 *     int expected_a_eq;
 *     bool expected_b_small;
 *     size_t ret_val;
 * })
 *
 * T_MOCK_SET_PERM_FUNC(size_t, foobar, (int a, char b)) {
 *     fb_call call = dequeue_fb_call();
 *     T_ASSERT_EQ(a, call.expected_a_eq, "a arg");
 *     if (call.expected_b_small)
 *         T_ASSERT_LE(b, 127, "b arg too big");
 *     return call.ret_val;
 * }
 *
 * // in the test we set up the expected calls before calling the code that ends up in the mock
 * T_DECL(test, "test") {
 *     enqueue_fb_call( (fb_call){ .expected_a_eq = 1,  .expected_b_small = true,  .ret_val = 3 });
 * 	   enqueue_fb_call( (fb_call){ .expected_a_eq = 10, .expected_b_small = false, .ret_val = 30 });
 *     // ... call into XNU which will call foobar()
 *     assert_empty_fb_call(); // check all calls were consumed
 * }
 */

#define _T_MOCK_CALL_LST(type_name)  _lst_ ## type_name

#define T_MOCK_CALL_QUEUE(type_name, struct_body)                                         \
    typedef struct s_ ## type_name struct_body type_name;                                 \
    struct _node_ ## type_name {                                                          \
        STAILQ_ENTRY(_node_ ## type_name) next;                                           \
        type_name d;                                                                      \
    };                                                                                    \
    static STAILQ_HEAD(, _node_ ## type_name) _T_MOCK_CALL_LST(type_name) =               \
        STAILQ_HEAD_INITIALIZER(_T_MOCK_CALL_LST(type_name));                             \
    static void enqueue_ ## type_name (type_name value) {                                 \
        struct _node_ ## type_name *node = calloc(1, sizeof(struct _node_ ## type_name)); \
        node->d = value;                                                                  \
        STAILQ_INSERT_TAIL(&_T_MOCK_CALL_LST(type_name), node, next);                     \
    }                                                                                     \
    static type_name dequeue_ ## type_name (void) {                                       \
        struct _node_ ## type_name *node = STAILQ_FIRST(&_T_MOCK_CALL_LST(type_name));    \
        T_QUIET; T_ASSERT_NOTNULL(node, "consumed too many " #type_name);                 \
        type_name d = node->d;                                                            \
        STAILQ_REMOVE_HEAD(&_T_MOCK_CALL_LST(type_name), next);                           \
        free(node);                                                                       \
        return d;                                                                         \
    }                                                                                     \
    static void assert_empty_ ## type_name (void) {                                       \
        T_QUIET; T_ASSERT_TRUE( STAILQ_EMPTY(&_T_MOCK_CALL_LST(type_name)),               \
                  "calls not fully consumed " #type_name);                                \
    }                                                                                     \
    static void clear_ ## type_name (void) {                                              \
        STAILQ_INIT(&_T_MOCK_CALL_LST(type_name));                                        \
    }


/* Overloadable function support
 * There's a difficulty with interposing a function that is defined with __attribute__((overloadable))
 * since using just the function name as an expression is ambiguous. The solution is to assign the
 * function name to a variable, this forces the compiler to select the right overload and get its address.
 * That address is then used for interposing.
 * Adding __attribute__((overloadable)) to a function definition tells the compiler to create a mangled
 * symbol for the it. A binary can have several __attribute__((overloadable)) functions of the
 * same name, as well as a single one of that name without __attribute__((overloadable)) which will be
 * not mangled.
 * mocking the functions with __attribute__((overloadable)) should be done with T_MOCK_OVERLOAD().
 * mocking the function without it should be done with T_MOCK_OVERLOAD_NOATTR().
 * Overloadable functions are not supported in T_MOCK()
 *
 * Example:
 * extern __attribute__((overloadable)) void overloaded_func(int a);
 * extern __attribute__((overloadable)) void overloaded_func(double a);
 * extern                               void overloaded_func(char* a);
 * extern                               void non_overloaded_func(int a);
 *
 * // mocks for these definitions:
 * T_MOCK_OVERLOAD(void, overloaded_func, (int a)) { ... }
 * T_MOCK_OVERLOAD(void, overloaded_func, (double a)) { ... }
 * T_MOCK_OVERLOAD_NOATTR(void, overloaded_func, (char* a)) { ... }
 * T_MOCK_INTERNAL(void, non_overloadede_func, (int a)) { ... }
 */

// this is here temporarily until it's added to dyld-interposing.h rdar://151219382
#define _DYLD_INTERPOSE_PTR(_replacement, _replacee) \
   __attribute__((used)) static struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
	    __attribute__ ((section ("__DATA,__interpose,interposing"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)_replacee };


#define _T_MOCK_OVERLOAD(attr, ret, name, unique_id, args)                    \
    extern attr ret name args;                                                \
	ret (*const name ## unique_id) args = name;                               \
	ret MOCK_ ## name ## unique_id args;                                      \
	_DYLD_INTERPOSE_PTR(MOCK_ ## name ## unique_id, name ## unique_id)        \
	ret MOCK_ ## name ## unique_id args

#define _T_MOCK_OVERLOAD2(attr, ret, name, unique_id, args) _T_MOCK_OVERLOAD(attr, ret, name, unique_id, args)
#define T_MOCK_OVERLOAD(ret, name, args)  _T_MOCK_OVERLOAD2(__attribute__((overloadable)), ret, name, __COUNTER__, args)
#define T_MOCK_OVERLOAD_NOATTR(ret, name, args)  _T_MOCK_OVERLOAD2(, ret, name, __COUNTER__, args)

/* Private mocks (pmocks)
 *
 * A test can define its own mocks if they are not already defined in one of the .c files in tests/unit/mocks/
 * which are compiled into libmocks.dylib
 *
 * Example: test.c
 *     PMOCKS_START
 *
 *     T_MOCK_PRIVATE(size_t, foobar, (int a, char b), (a, b), {
 *         // override for foobar()
 *     });
 *
 *     PMOCKS_END
 *
 * - There can be multiple PMOCKS_START|END sections in a test.c
 * - The text inside the PMOCKS_START|END sections is pasted into a separate .c file and compiled
 * separately from the test.c file it is in.
 * - The code in the PMOCKS_START|END sections should be self-contained and should have #includes for
 * Any types or definitions that it depends on.
 * - If the implementation is complex and depends on things from the test, the implementation in T_MOCK_PRIVATE()
 * can remain empty and then the test can use T_MOCK_SET_*() to override it.
 * - T_MOCK_PRIVATE() must not appear outside a PMOCKS_START|END section
 */


#if defined(UT_BUILDING_LIBMOCKS)

#elif defined(UT_EXTRACTING_PMOCKS)
  // A test.c file should not contain T_MOCK, T_MOCK_F
  #undef T_MOCK
  #undef T_MOCK_F
  // PMOCKS_START|END markers and T_MOCK_PRIVATE() should be undefined so that they survive the preprocessor

#elif defined (UT_BUILDING_PMOCKS)
  // the PMOCKS_START|END markers should not appear in the extracted pmocks.c file so we don't define them.
  // T_MOCK_F remain defined to implement the mocks

  // Define a private mock inside a PMOCKS_START|END block
  // The mock body is in a macro argument so that it can be turned to nothing when building the test.c
  // It also needs to be a __VA_ARGS__ so that the preprocessor not get confused by commas in the body
  #define T_MOCK_PRIVATE(ret, name, args_def, args_invoke, ...) \
      T_MOCK_F(ret, name, args_def, args_invoke) __VA_ARGS__

#else // it's a test.c
  // When building the test.c, PMOCKS_START|END should should turn to nothing so that
  // they don't interfer with compilation
  #define PMOCKS_START
  #define PMOCKS_END
  // A test.c file should not contain T_MOCK, T_MOCK_F
  #undef T_MOCK
  #undef T_MOCK_F

  // T_MOCK_PRIVATE turns to the mock declaration when it remains in the test.c so that
  // the test.c can call it and override it with T_MOCK_SET_CALLBACK.
  #define T_MOCK_PRIVATE(ret, name, args_def, args_invoke, ...) \
      T_MOCK_DECLARE(ret, name, args_def);

#endif

__END_DECLS
/* END IGNORE CODESTYLE */
