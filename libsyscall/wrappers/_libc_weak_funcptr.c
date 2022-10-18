//
//  _libc_weak_funcptr.c
//  Libsyscall_static
//
//  Created by Ian Fang on 11/30/21.
//
//  dyld needs the following definitions to link against Libsyscall_static.
//  When building Libsyscall_dynamic, the weak symbols below will get overridden
//  by actual implementation.
//

#include "_libkernel_init.h"

__attribute__((weak, visibility("hidden")))
void *
malloc(__unused size_t size)
{
	return NULL;
}

__attribute__((weak, visibility("hidden")))
mach_msg_size_t
voucher_mach_msg_fill_aux(__unused mach_msg_aux_header_t *aux_hdr,
    __unused mach_msg_size_t sz)
{
	return 0;
}

__attribute__((weak, visibility("hidden")))
boolean_t
voucher_mach_msg_fill_aux_supported(void)
{
	return FALSE;
}
