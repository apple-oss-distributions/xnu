#!/usr/sbin/dtrace -s

vminfo:::vm_map_delete_permanent_prot_none
{
	printf("%d[%s]: keeping \"deleted\" permanent mapping [ 0x%llx - 0x%llx ] prot 0x%x/0x%x -> 0/0",
	       pid,
	       execname,
	       (uint64_t) arg1,
	       (uint64_t) arg2,
	       arg3,
	       arg4);
	stack();
	ustack();
}
