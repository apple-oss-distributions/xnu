#ifndef _KERN_MPQUEUE_H
#define _KERN_MPQUEUE_H
#include <kern/locks.h>

__BEGIN_DECLS

#ifdef  MACH_KERNEL_PRIVATE

#include <kern/priority_queue.h>

/*----------------------------------------------------------------*/
/*
 *	Define macros for queues with locks.
 */
struct mpqueue_head {
	struct queue_entry      head;           /* header for queue */
	struct priority_queue_deadline_min mpq_pqhead;
	uint64_t                earliest_soft_deadline;
	uint64_t                count;
	lck_ticket_t            lock_data;
};

typedef struct mpqueue_head     mpqueue_head_t;

#define mpqueue_init(q, lck_grp, lck_attr)              \
MACRO_BEGIN                                             \
	queue_init(&(q)->head);                         \
	lck_ticket_init(&(q)->lock_data, lck_grp);      \
	priority_queue_init(&(q)->mpq_pqhead);          \
MACRO_END

#define mpenqueue_tail(q, elt)                          \
MACRO_BEGIN                                             \
	lck_ticket_lock(&(q)->lock_data, LCK_GRP_NULL); \
	enqueue_tail(&(q)->head, elt);                  \
	lck_ticket_unlock(&(q)->lock_data);             \
MACRO_END

#define mpdequeue_head(q, elt)                          \
MACRO_BEGIN                                             \
	lck_ticket_lock(&(q)->lock_data, LCK_GRP_NULL); \
	if (queue_empty(&(q)->head))                    \
	        *(elt) = 0;                             \
	else                                            \
	        *(elt) = dequeue_head(&(q)->head);      \
	lck_ticket_unlock(&(q)->lock_data);             \
MACRO_END

#endif  /* MACH_KERNEL_PRIVATE */

__END_DECLS


#endif /* _KERN_QUEUE_H */
