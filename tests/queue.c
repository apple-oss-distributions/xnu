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
