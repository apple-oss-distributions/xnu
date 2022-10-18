/* Copyright (c) (2012,2015,2016,2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to
 * people who accept that license. IMPORTANT:  Any license rights granted to you by
 * Apple Inc. (if any) are limited to internal use within your organization only on
 * devices and computers you own or control, for the sole purpose of verifying the
 * security characteristics and correct functioning of the Apple Software.  You may
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
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

#ifndef _CORECRYPTO_CC_MACROS_H_
#define _CORECRYPTO_CC_MACROS_H_

#include <corecrypto/cc_config.h>

#ifndef __CC_DEBUG_ASSERT_COMPONENT_NAME_STRING
#define __CC_DEBUG_ASSERT_COMPONENT_NAME_STRING ""
#endif

#ifndef __CC_DEBUG_ASSERT_PRODUCTION_CODE
#define __CC_DEBUG_ASSERT_PRODUCTION_CODE !CORECRYPTO_DEBUG
#endif

#if CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS

#if !CC_KERNEL
    #include <string.h> // for strstr
#endif // !CC_KERNEL

CC_UNUSED static char *
cc_strstr(const char *file)
{
#if CC_KERNEL
	(void) file;
#else
	const char cc_char[] = "corecrypto";
	char *p = strstr(file, cc_char);
	if (p) {
		return p + strlen(cc_char) + 1;
	}
#endif
	return NULL;
}

#define __CC_DEBUG_REQUIRE_MESSAGE(name, assertion, label, message, file, line, value) \
{char *___t = cc_strstr(file); cc_printf( "require: %s, %s%s:%d\n", assertion, (message!=0) ? message : "", ___t==NULL?file:___t, line);}

#endif // CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS

#ifndef cc_require
#if (__CC_DEBUG_ASSERT_PRODUCTION_CODE) || (!CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS)
  #if defined(_WIN32) && defined (__clang__)
    #define cc_require(assertion, exceptionLabel) \
       do { \
	   if (!(assertion) ) { \
	      goto exceptionLabel; \
	   } \
	} while ( 0 )
  #else
    #define cc_require(assertion, exceptionLabel) \
	do { \
	    if ( __builtin_expect(!(assertion), 0) ) { \
	        goto exceptionLabel; \
	    } \
	} while ( 0 )
 #endif
#else
    #define cc_require(assertion, exceptionLabel) \
	do { \
	    if ( __builtin_expect(!(assertion), 0) ) { \
	        __CC_DEBUG_REQUIRE_MESSAGE(__CC_DEBUG_ASSERT_COMPONENT_NAME_STRING, \
	            #assertion, #exceptionLabel, 0, __FILE__, __LINE__,  0); \
	        goto exceptionLabel; \
	    } \
	} while ( 0 )
#endif
#endif

#ifndef cc_require_action
#if __CC_DEBUG_ASSERT_PRODUCTION_CODE || (!CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS)
  #if defined(_WIN32) && defined(__clang__)
    #define cc_require_action(assertion, exceptionLabel, action)                \
	do                                                                      \
	{                                                                       \
	    if (!(assertion))                                                   \
	    {                                                                   \
	        {                                                               \
	            action;                                                     \
	        }                                                               \
	        goto exceptionLabel;                                            \
	    }                                                                   \
	} while ( 0 )
  #else
    #define cc_require_action(assertion, exceptionLabel, action)                \
	do                                                                      \
	{                                                                       \
	    if ( __builtin_expect(!(assertion), 0) )                            \
	    {                                                                   \
	        {                                                               \
	            action;                                                     \
	        }                                                               \
	        goto exceptionLabel;                                            \
	    }                                                                   \
	} while ( 0 )
  #endif
#else
    #define cc_require_action(assertion, exceptionLabel, action)                \
	do                                                                      \
	{                                                                       \
	    if ( __builtin_expect(!(assertion), 0) )                            \
	    {                                                                   \
	        __CC_DEBUG_REQUIRE_MESSAGE(                                      \
	            __CC_DEBUG_ASSERT_COMPONENT_NAME_STRING,                    \
	            #assertion, #exceptionLabel, 0,   __FILE__, __LINE__, 0);   \
	        {                                                               \
	            action;                                                     \
	        }                                                               \
	        goto exceptionLabel;                                            \
	    }                                                                   \
	} while ( 0 )
#endif
#endif

#ifndef cc_require_or_return
#if (__CC_DEBUG_ASSERT_PRODUCTION_CODE) || (!CORECRYPTO_DEBUG_ENABLE_CC_REQUIRE_PRINTS)
  #if defined(_WIN32) && defined (__clang__)
    #define cc_require_or_return(assertion, value)                                  \
       do {                                                                         \
	   if (!(assertion) ) {                                                     \
	      return value;                                                         \
	   }                                                                        \
	} while ( 0 )
  #else
    #define cc_require_or_return(assertion, value)                                  \
	do {                                                                        \
	    if ( __builtin_expect(!(assertion), 0) ) {                              \
	        return value;                                                       \
	    }                                                                       \
	} while ( 0 )
 #endif
#else
    #define cc_require_or_return(assertion, value)                                  \
	do {                                                                        \
	    if ( __builtin_expect(!(assertion), 0) ) {                              \
	        __CC_DEBUG_REQUIRE_MESSAGE(__CC_DEBUG_ASSERT_COMPONENT_NAME_STRING, \
	            #assertion, #exceptionLabel, 0, __FILE__, __LINE__,  0);        \
	        return value;                                                       \
	    }                                                                       \
	} while ( 0 )
#endif
#endif

#endif /* _CORECRYPTO_CC_MACROS_H_ */
