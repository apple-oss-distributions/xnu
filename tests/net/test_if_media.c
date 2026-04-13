/*
 * Copyright (c) 2019 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <darwintest.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_media.h>
#include <netinet/in.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

T_GLOBAL_META(
	T_META_NAMESPACE("xnu.net"),
	T_META_RADAR_COMPONENT_NAME("xnu"),
	T_META_RADAR_COMPONENT_VERSION("networking"),
	T_META_ASROOT(true),
	T_META_OWNER("vlubet")
	);

#define IFM_ETHER_TMASK IFM_TMASK
#define IFM_ETHER_TMASK_NAME "IFM_TMASK"

struct ifmd_list_info {
	const char *list_name;
	const char *field_name;
	unsigned int mask;
	const char *mask_name;
	struct ifmedia_description ifmds[];
};

static struct ifmd_list_info ifm_type_descriptions = {
	.list_name = "IFM_TYPE_DESCRIPTIONS",
	.field_name = "type",
	.mask = IFM_NMASK,
	.mask_name = "IFM_NMASK",
	.ifmds = IFM_TYPE_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_ethernet_descriptions = {
	.list_name = "IFM_SUBTYPE_ETHERNET_DESCRIPTIONS",
	.field_name = "Ethernet subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_ETHERNET_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_ethernet_aliases = {
	.list_name = "IFM_SUBTYPE_ETHERNET_ALIASES",
	.field_name = "Ethernet subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_ETHERNET_ALIASES,
};

static struct ifmd_list_info ifm_subtype_ethernet_option_descriptions = {
	.list_name = "IFM_SUBTYPE_ETHERNET_OPTION_DESCRIPTIONS",
	.field_name = "Ethernet option",
	.mask = IFM_OMASK,
	.mask_name = "IFM_OMASK",
	.ifmds = IFM_SUBTYPE_ETHERNET_OPTION_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_tokenring_descriptions = {
	.list_name = "IFM_SUBTYPE_TOKENRING_DESCRIPTIONS",
	.field_name = "Tokenring subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_TOKENRING_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_tokenring_aliases = {
	.list_name = "IFM_SUBTYPE_TOKENRING_ALIASES",
	.field_name = "Tokenring subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_TOKENRING_ALIASES,
};

static struct ifmd_list_info ifm_subtype_tokenring_option_descriptions = {
	.list_name = "IFM_SUBTYPE_TOKENRING_OPTION_DESCRIPTIONS",
	.field_name = "Tokenring option",
	.mask = IFM_OMASK,
	.mask_name = "IFM_OMASK",
	.ifmds = IFM_SUBTYPE_TOKENRING_OPTION_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_fddi_descriptions = {
	.list_name = "IFM_SUBTYPE_FDDI_DESCRIPTIONS",
	.field_name = "FDDI subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_FDDI_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_fddi_aliases = {
	.list_name = "IFM_SUBTYPE_FDDI_ALIASES",
	.field_name = "FDDI subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_FDDI_ALIASES,
};

static struct ifmd_list_info ifm_subtype_fddi_options = {
	.list_name = "IFM_SUBTYPE_FDDI_OPTION_DESCRIPTIONS",
	.field_name = "FDDI option",
	.mask = IFM_OMASK,
	.mask_name = "IFM_OMASK",
	.ifmds = IFM_SUBTYPE_FDDI_OPTION_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_ieee80211_descriptions = {
	.list_name = "IFM_SUBTYPE_IEEE80211_DESCRIPTIONS",
	.field_name = "IEEE80211 subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_IEEE80211_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_ieee80211_option_descriptions = {
	.list_name = "IFM_SUBTYPE_IEEE80211_OPTION_DESCRIPTIONS",
	.field_name = "IEEE80211 options",
	.mask = IFM_OMASK,
	.mask_name = "IFM_OMASK",
	.ifmds = IFM_SUBTYPE_IEEE80211_OPTION_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_shared_descriptions = {
	.list_name = "IFM_SUBTYPE_SHARED_DESCRIPTIONS",
	.field_name = "shared subtype",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_SHARED_DESCRIPTIONS,
};

static struct ifmd_list_info ifm_subtype_shared_aliases = {
	.list_name = "IFM_SUBTYPE_SHARED_ALIASES",
	.field_name = "shared alias",
	.mask = IFM_TMASK,
	.mask_name = "IFM_TMASK",
	.ifmds = IFM_SUBTYPE_SHARED_ALIASES,
};

static struct ifmd_list_info ifm_subtype_shared_options = {
	.list_name = "IFM_SHARED_OPTION_DESCRIPTIONS",
	.field_name = "shared option",
	.mask = IFM_GMASK,
	.mask_name = "IFM_GMASK",
	.ifmds = IFM_SHARED_OPTION_DESCRIPTIONS,
};

static void
check_ifmedia_description_list(struct ifmd_list_info *ifmd_list_info)
{
	struct ifmedia_description *ifmd;

	T_LOG("Checking %s", ifmd_list_info->list_name);

	for (ifmd = ifmd_list_info->ifmds; ifmd->ifmt_string != NULL; ifmd++) {
		T_QUIET;
		T_EXPECT_EQ(ifmd->ifmt_word & ~ifmd_list_info->mask, 0u,
		    "ifmedia type %s (0x%x) should be inside %s range (0x%x)",
		    ifmd->ifmt_string, ifmd->ifmt_word, ifmd_list_info->mask_name,
		    ifmd_list_info->mask);
	}
}

static int
print_ethernet_subtype(int media, struct ifmd_list_info *ifmd_list_info)
{
	struct ifmedia_description *ifmd;

	for (ifmd = ifmd_list_info->ifmds; ifmd->ifmt_string != NULL; ifmd++) {
		if (IFM_SUBTYPE(media) == ifmd->ifmt_word) {
			T_LOG("subtype %d: %s", IFM_SUBTYPE(media), ifmd->ifmt_string);
			return 0;
		}
	}
	return -1;
}

/*
 * On some platforms with DEBUG kernel, we need to wait a while
 */
#define SIFCREATE_RETRY_COUNT 10
#define SIFCREATE_DELAY_MSECS 10

static int
create_feth(int s, char *ifname, size_t ifnamesize)
{
	int error = 0;
	struct ifreq ifr;
	int i;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	for (i = 1; i <= SIFCREATE_RETRY_COUNT; i++) {
		if ((error = ioctl(s, SIOCIFCREATE2, &ifr)) != 0) {
			if (errno == EBUSY && i + 1 <= SIFCREATE_RETRY_COUNT) {
				T_LOG("ioctl(SIOCIFCREATE2, %s) retry %d in %d msecs",
				    ifr.ifr_name, i + 1, SIFCREATE_DELAY_MSECS);
				usleep(SIFCREATE_DELAY_MSECS * 1000);
			} else {
				T_LOG("ioctl(SIOCIFCREATE2, %s) unexpected failure after %d tr%s",
				    ifr.ifr_name, i, i > 1 ? "ies" : "y");
				break;
			}
		} else {
			(void)strlcpy(ifname, ifr.ifr_name, ifnamesize);
			break;
		}
	}
	return error;
}

static int
destroy_feth(int s, const char *ifname)
{
	struct ifreq ifr;

	memset(&ifr, 0, sizeof(ifr));
	(void)strlcpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	if (ioctl(s, SIOCIFDESTROY, &ifr) != 0) {
		T_LOG("ioctl(SIOCIFDESTROY, %s) failed: %s", ifr.ifr_name, strerror(errno));
		return -1;
	}
	T_LOG("destroyed interface %s", ifname);

	return 0;
}

static void
check_feth_supported_media(unsigned long cmd, const char *cmd_str)
{
	char ifname[IFNAMSIZ];
	struct ifmediareq ifmr;
	int *media_list = NULL, i;
	int s = -1;
	bool clone_ok = false;

	T_LOG("Checking %s (0x%08lx)", cmd_str, cmd);

	s = socket(AF_INET, SOCK_DGRAM, 0);
	T_ASSERT_POSIX_SUCCESS(s, "socket()");

	(void)strlcpy(ifname, "feth", sizeof(ifname));
	if (create_feth(s, ifname, sizeof(ifname)) != 0) {
		T_SKIP("could not clone interface %s", ifname);
	}
	T_LOG("created interface %s", ifname);
	clone_ok = true;

	memset(&ifmr, 0, sizeof(ifmr));
	(void)strlcpy(ifmr.ifm_name, ifname, sizeof(ifmr.ifm_name));
	T_ASSERT_POSIX_SUCCESS(ioctl(s, cmd, (caddr_t)&ifmr),
	    "ioctl(%s, %s)", cmd_str, ifmr.ifm_name);

	T_ASSERT_GT(ifmr.ifm_count, 0, "should have media types for %s", ifmr.ifm_name);

	media_list = (int *)calloc(ifmr.ifm_count, sizeof(int));
	T_ASSERT_NOTNULL(media_list, "calloc()");

	ifmr.ifm_ulist = media_list;
	T_ASSERT_POSIX_SUCCESS(ioctl(s, cmd, (caddr_t)&ifmr),
	    "ioctl(%s, %s) get media list", cmd_str, ifmr.ifm_name);

	for (i = 0; i < ifmr.ifm_count; i++) {
		if (print_ethernet_subtype(media_list[i], &ifm_subtype_ethernet_descriptions) == 0) {
			/* Found in ethernet descriptions */
		} else if (print_ethernet_subtype(media_list[i], &ifm_subtype_shared_descriptions) == 0) {
			/* Found in shared descriptions */
		} else {
			T_FAIL("subtype %d unknown", IFM_SUBTYPE(media_list[i]));
		}
	}

	free(media_list);

	if (clone_ok) {
		T_ASSERT_POSIX_SUCCESS(destroy_feth(s, ifname), "destroy_feth");
	}
	if (s != -1) {
		close(s);
	}
}

T_DECL(test_if_media_descriptions,
    "test if_media description tables are valid",
    T_META_CHECK_LEAKS(false))
{
	check_ifmedia_description_list(&ifm_type_descriptions);

	check_ifmedia_description_list(&ifm_subtype_ethernet_descriptions);
	check_ifmedia_description_list(&ifm_subtype_ethernet_aliases);
	check_ifmedia_description_list(&ifm_subtype_ethernet_option_descriptions);

	check_ifmedia_description_list(&ifm_subtype_tokenring_descriptions);
	check_ifmedia_description_list(&ifm_subtype_tokenring_aliases);
	check_ifmedia_description_list(&ifm_subtype_tokenring_option_descriptions);

	check_ifmedia_description_list(&ifm_subtype_fddi_descriptions);
	check_ifmedia_description_list(&ifm_subtype_fddi_aliases);
	check_ifmedia_description_list(&ifm_subtype_fddi_options);

	check_ifmedia_description_list(&ifm_subtype_ieee80211_descriptions);
	check_ifmedia_description_list(&ifm_subtype_ieee80211_option_descriptions);

	check_ifmedia_description_list(&ifm_subtype_shared_descriptions);
	check_ifmedia_description_list(&ifm_subtype_shared_aliases);
	check_ifmedia_description_list(&ifm_subtype_shared_options);

	T_PASS("All if_media description tables are valid");
}

T_DECL(test_if_media_feth,
    "test feth interface media types",
    T_META_CHECK_LEAKS(false))
{
	check_feth_supported_media(SIOCGIFMEDIA, "SIOCGIFMEDIA");
#ifdef SIOCGIFXMEDIA
	check_feth_supported_media(SIOCGIFXMEDIA, "SIOCGIFXMEDIA");
#endif /* SIOCGIFXMEDIA */

	T_PASS("feth interface media types are valid");
}
