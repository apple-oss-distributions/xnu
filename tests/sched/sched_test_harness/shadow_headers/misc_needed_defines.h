// Copyright (c) 2023 Apple Inc.  All rights reserved.

#ifndef _MISC_NEEDED_DEFINES_H_
#define _MISC_NEEDED_DEFINES_H_

/* Defines from osfmk/mach/mach_types.h */

#include <mach/clock_types.h>

typedef struct task                     *task_t;
typedef struct thread                   *thread_t;
typedef struct processor                *processor_t;
typedef struct processor_set            *processor_set_t;

#define TASK_NULL               ((task_t) 0)
#define THREAD_NULL             ((thread_t) 0)
#define PROCESSOR_NULL          ((processor_t) 0)

typedef int             kern_return_t;

/* Defines from osfmk/kern/timer_call.h */
typedef void            *timer_call_param_t;

/* Defines from osfmk/kern/ast.h */
typedef uint32_t ast_t;
#define AST_PREEMPT             0x01
#define AST_QUANTUM             0x02
#define AST_URGENT              0x04
#define AST_NONE                0x00

/* Defines from osfmk/kern/kern_types.h */
typedef struct run_queue               *run_queue_t;

#endif  /* _MISC_NEEDED_DEFINES_H_ */
