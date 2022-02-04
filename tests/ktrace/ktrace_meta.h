#ifndef KTRACE_META_H
#define KTRACE_META_H

#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.ktrace"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("ktrace"),
	T_META_OWNER("mwidmann"),
	T_META_ASROOT(true),
	T_META_CHECK_LEAKS(false));

#endif // !defined(KTRACE_META_H)
