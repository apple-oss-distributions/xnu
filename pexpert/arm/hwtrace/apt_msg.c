/*
 * Copyright (c) 2024 Apple Inc. All rights reserved.
 */

#include <pexpert/arm64/board_config.h>
#include <pexpert/arm64/apt_msg.h>

#define NEED_STUB 1


#ifdef NEED_STUB
void
apt_msg_init(void)
{
}

uint8_t
apt_msg_policy(void)
{
	return 0;
}

void
apt_msg_init_cpu(void)
{
}

void
apt_msg_emit(__unused int ns, __unused int type, __unused int num_payloads, __unused uint64_t *payloads)
{
}
#endif // NEED_STUB
