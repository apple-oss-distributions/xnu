#include <libkern/libkern.h>
#include <libkern/section_keywords.h>
#include <libkern/image4/dlxk.h>

#pragma mark Module Globals
SECURITY_READ_ONLY_LATE(const image4_dlxk_interface_t *) _dlxk = NULL;

#pragma mark KPI
void
image4_dlxk_link(const image4_dlxk_interface_t *dlxk)
{
	if (_dlxk) {
		panic("image4 dlxk interface already set");
	}
	_dlxk = dlxk;
}

const image4_dlxk_interface_t *
image4_dlxk_get(image4_struct_version_t v)
{
	if (v > _dlxk->dlxk_version) {
		return NULL;
	}
	return _dlxk;
}
