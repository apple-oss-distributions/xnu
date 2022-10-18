#!/usr/sbin/dtrace -s

vminfo::suspicious_task_vm_info_count:
{
	printf("%d[%s]: task_info() called with count=%d > TASK_VM_INFO_COUNT=%d",
	       pid,
	       execname,
	       arg1,
	       arg2);
	stack();
	ustack();
}
