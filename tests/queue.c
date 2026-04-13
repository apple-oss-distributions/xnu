#include <darwintest.h>

#define DEVELOPMENT 0
#define DEBUG 0
#define KERNEL_PRIVATE 1
#define XNU_KERNEL_PRIVATE 1
#define KERNEL 1
#include <../osfmk/machine/trap.h>
#include <../osfmk/kern/queue.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.kern"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("all"));

struct qe_t2 {
	int           a;
	queue_chain_t link;
	int           b;
};

static void
check_queue(queue_t q, int *values, int count)
{
	struct qe_t2 *e;
	int i = 0;

	queue_iterate(q, e, struct qe_t2 *, link) {
		T_QUIET; T_EXPECT_LT(i, count, "should have elems");
		T_QUIET; T_EXPECT_EQ(values[i], e->a, "check elem");
		values++;
		count--;
	}
	T_QUIET; T_EXPECT_EQ(count, i, "queue is valid");
}


T_DECL(queue_type2, "test type 2 queues")
{
	static queue_head_t head;
	static struct qe_t2 elems[4];
	struct qe_t2 *e;

	queue_init(&head);

	for (int i = 0; i < 4; i++) {
		e = &elems[i];
		e->a = e->b = i + 1;
		queue_enter(&head, e, struct qe_t2 *, link);
		check_queue(&head, (int[]){ 1, 2, 3, 4, }, i + 1);
	}
	T_PASS("building list (1, 2, 3, 4)");

	queue_remove_first(&head, e, struct qe_t2 *, link);
	T_EXPECT_EQ(e, &elems[0], "removed elem 1");
	check_queue(&head, (int[]){ 2, 3, 4, }, 3);

	queue_remove_first(&head, e, struct qe_t2 *, link);
	T_EXPECT_EQ(e, &elems[1], "removed elem 2");
	check_queue(&head, (int[]){ 3, 4, }, 2);

	queue_remove_last(&head, e, struct qe_t2 *, link);
	T_EXPECT_EQ(e, &elems[3], "removed elem 4");
	check_queue(&head, (int[]){ 3 }, 1);

	e = &elems[2];
	queue_remove(&head, e, struct qe_t2 *, link);
	T_EXPECT_EQ(e, &elems[2], "removed elem 3");
	check_queue(&head, (int[]){ }, 0);

	queue_enter(&head, &elems[0], struct qe_t2 *, link);
	check_queue(&head, (int[]){ 1, }, 1);

	queue_enter_first(&head, &elems[1], struct qe_t2 *, link);
	check_queue(&head, (int[]){ 2, 1, }, 2);

	queue_enter(&head, &elems[2], struct qe_t2 *, link);
	check_queue(&head, (int[]){ 2, 1, 3, }, 3);
}

T_DECL(queue_type2_extend, "test extending type 2 queues")
{
	static queue_head_t head1;
	static queue_head_t head2;
	static struct qe_t2 elems[8];
	struct qe_t2 *e;

	queue_init(&head1);
	queue_init(&head2);

	// Build first queue with elements A, B, C, D (values 1-4)
	for (int i = 0; i < 4; i++) {
		e = &elems[i];
		e->a = e->b = i + 1;
		queue_enter(&head1, e, struct qe_t2 *, link);
	}
	check_queue(&head1, (int[]){ 1, 2, 3, 4, }, 4);
	T_PASS("built first queue (1, 2, 3, 4)");

	// Build second queue with elements E, F, G, H (values 5-8)
	for (int i = 4; i < 8; i++) {
		e = &elems[i];
		e->a = e->b = i + 1;
		queue_enter(&head2, e, struct qe_t2 *, link);
	}
	check_queue(&head2, (int[]){ 5, 6, 7, 8, }, 4);
	T_PASS("built second queue (5, 6, 7, 8)");

	// Append second queue to first
	queue_extend_last(&head1, &head2, struct qe_t2 *, link);

	// Verify the combined queue contains all elements in correct order
	check_queue(&head1, (int[]){ 1, 2, 3, 4, 5, 6, 7, 8, }, 8);
	T_PASS("appended second queue to first (1, 2, 3, 4, 5, 6, 7, 8)");

	// Verify second queue is now empty
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should be empty after append");

	// Test case: append non-empty queue to an empty queue
	// head2 is now empty, rebuild it with elements 1-3
	for (int i = 0; i < 3; i++) {
		e = &elems[i];
		queue_enter(&head2, e, struct qe_t2 *, link);
	}
	static queue_head_t head3;
	queue_init(&head3);
	T_EXPECT_TRUE(queue_empty(&head3), "head3 should start empty");

	queue_extend_last(&head3, &head2, struct qe_t2 *, link);
	check_queue(&head3, (int[]){ 1, 2, 3, }, 3);
	T_PASS("appending non-empty queue to empty queue works");
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should be empty after append");

	// Test case: append empty queue to non-empty queue
	// head2 is empty, head3 has elements 1-3
	T_EXPECT_TRUE(queue_empty(&head2), "head2 should be empty");
	queue_extend_last(&head3, &head2, struct qe_t2 *, link);
	check_queue(&head3, (int[]){ 1, 2, 3, }, 3);
	T_PASS("appending empty queue to non-empty queue leaves destination unchanged");
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should remain empty");

	// Test case: append empty queue to empty queue
	static queue_head_t head4;
	queue_init(&head4);
	queue_extend_last(&head4, &head2, struct qe_t2 *, link);
	T_EXPECT_TRUE(queue_empty(&head4), "destination queue should remain empty");
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should remain empty");
	T_PASS("appending empty queue to empty queue leaves both queues empty");
}

T_DECL(queue_type2_prepend, "test prepending type 2 queues")
{
	static queue_head_t head1;
	static queue_head_t head2;
	static struct qe_t2 elems[8];
	struct qe_t2 *e;

	queue_init(&head1);
	queue_init(&head2);

	// Build first queue with elements A, B, C, D (values 1-4)
	for (int i = 0; i < 4; i++) {
		e = &elems[i];
		e->a = e->b = i + 1;
		queue_enter(&head1, e, struct qe_t2 *, link);
	}
	check_queue(&head1, (int[]){ 1, 2, 3, 4, }, 4);
	T_PASS("built first queue (1, 2, 3, 4)");

	// Build second queue with elements E, F, G, H (values 5-8)
	for (int i = 4; i < 8; i++) {
		e = &elems[i];
		e->a = e->b = i + 1;
		queue_enter(&head2, e, struct qe_t2 *, link);
	}
	check_queue(&head2, (int[]){ 5, 6, 7, 8, }, 4);
	T_PASS("built second queue (5, 6, 7, 8)");

	// Prepend second queue to first
	queue_extend_first(&head1, &head2, struct qe_t2 *, link);

	// Verify the combined queue contains all elements in correct order (prepended, so 5-8 comes before 1-4)
	check_queue(&head1, (int[]){ 5, 6, 7, 8, 1, 2, 3, 4, }, 8);
	T_PASS("prepended second queue to first (5, 6, 7, 8, 1, 2, 3, 4)");

	// Verify second queue is now empty
	T_ASSERT_TRUE(queue_empty(&head2), "source queue should be empty after prepend");

	// Test case: prepend non-empty queue to an empty queue
	// head2 is now empty, rebuild it with elements 1-3
	for (int i = 0; i < 3; i++) {
		e = &elems[i];
		queue_enter(&head2, e, struct qe_t2 *, link);
	}
	static queue_head_t head3;
	queue_init(&head3);
	T_ASSERT_TRUE(queue_empty(&head3), "head3 should start empty");

	queue_extend_first(&head3, &head2, struct qe_t2 *, link);
	check_queue(&head3, (int[]){ 1, 2, 3, }, 3);
	T_PASS("prepending non-empty queue to empty queue works (1, 2, 3)");
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should be empty after prepend");

	// Test case: prepend empty queue to non-empty queue
	// head2 is empty, head3 has elements 1-3
	T_ASSERT_TRUE(queue_empty(&head2), "head2 should be empty");
	queue_extend_first(&head3, &head2, struct qe_t2 *, link);
	check_queue(&head3, (int[]){ 1, 2, 3, }, 3);
	T_PASS("prepending empty queue to non-empty queue leaves destination unchanged");
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should remain empty");

	// Test case: prepend empty queue to empty queue
	static queue_head_t head4;
	queue_init(&head4);
	queue_extend_first(&head4, &head2, struct qe_t2 *, link);
	T_EXPECT_TRUE(queue_empty(&head4), "destination queue should remain empty");
	T_EXPECT_TRUE(queue_empty(&head2), "source queue should remain empty");
	T_PASS("prepending empty queue to empty queue leaves both queues empty");
}
