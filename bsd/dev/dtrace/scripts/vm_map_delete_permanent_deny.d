#!/usr/sbin/dtrace -s

vminfo:::vm_map_delete_permanent_deny*
{
	printf("%d[%s]: denying mutation of permanent mapping [ 0x%llx - 0x%llx ] prot 0x%x/0x%x",
	       pid,
	       execname,
	       (uint64_t) arg1,
	       (uint64_t) arg2,
	       arg3,
	       arg4);
	stack();
	ustack();
}
