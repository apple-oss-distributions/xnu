/*
 * Copyright (c) 2020-2023 Apple Inc. All rights reserved.
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

#ifndef ioc_str_h
#define ioc_str_h

#include <sys/socket.h>
#include <sys/kern_event.h>
#include <sys/sockio.h>

#include <net/if.h>
#include <net/if_ppp.h>

#include <netinet/in.h>

#include <netinet6/in6_var.h>
#include <netinet6/nd6.h>

#define SIOC_LIST \
       X(SIOCGPPPSTATS) \
       X(SIOCGPPPCSTATS) \
       X(SIOCSIFADDR_IN6) \
       X(SIOCGIFADDR_IN6) \
       X(SIOCSIFDSTADDR_IN6) \
       X(SIOCSIFNETMASK_IN6) \
       X(SIOCGIFDSTADDR_IN6) \
       X(SIOCGIFNETMASK_IN6) \
       X(SIOCDIFADDR_IN6) \
       X(SIOCGIFPSRCADDR_IN6) \
       X(SIOCGIFPDSTADDR_IN6) \
       X(SIOCGIFAFLAG_IN6) \
       X(OSIOCGIFINFO_IN6) \
       X(SIOCGIFINFO_IN6) \
       X(SIOCSNDFLUSH_IN6) \
       X(SIOCGNBRINFO_IN6) \
       X(SIOCSPFXFLUSH_IN6) \
       X(SIOCSRTRFLUSH_IN6) \
       X(SIOCGIFALIFETIME_IN6) \
       X(SIOCSIFALIFETIME_IN6) \
       X(SIOCGIFSTAT_IN6) \
       X(SIOCGIFSTAT_ICMP6) \
       X(SIOCSDEFIFACE_IN6) \
       X(SIOCGDEFIFACE_IN6) \
       X(SIOCSIFINFO_FLAGS) \
       X(SIOCSSCOPE6) \
       X(SIOCGSCOPE6) \
       X(SIOCGSCOPE6DEF) \
       X(SIOCSIFPREFIX_IN6) \
       X(SIOCGIFPREFIX_IN6) \
       X(SIOCDIFPREFIX_IN6) \
       X(SIOCAIFPREFIX_IN6) \
       X(SIOCCIFPREFIX_IN6) \
       X(SIOCSGIFPREFIX_IN6) \
       X(SIOCPROTOATTACH_IN6) \
       X(SIOCPROTODETACH_IN6) \
       X(SIOCLL_START) \
       X(SIOCLL_STOP) \
       X(SIOCAUTOCONF_START) \
       X(SIOCAUTOCONF_STOP) \
       X(SIOCSETROUTERMODE_IN6) \
       X(SIOCGETROUTERMODE_IN6) \
       X(SIOCLL_CGASTART) \
       X(SIOCGIFCGAPREP_IN6) \
       X(SIOCSIFCGAPREP_IN6) \
       X(SIOCSIFADDR) \
       X(SIOCSIFDSTADDR) \
       X(SIOCSIFFLAGS) \
       X(SIOCGIFFLAGS) \
       X(SIOCSIFBRDADDR) \
       X(SIOCSIFNETMASK) \
       X(SIOCGIFMETRIC) \
       X(SIOCSIFMETRIC) \
       X(SIOCDIFADDR) \
       X(SIOCAIFADDR) \
       X(SIOCGIFADDR) \
       X(SIOCGIFDSTADDR) \
       X(SIOCGIFBRDADDR) \
       X(SIOCGIFCONF) \
       X(SIOCGIFNETMASK) \
       X(SIOCAUTOADDR) \
       X(SIOCAUTONETMASK) \
       X(SIOCARPIPLL) \
       X(SIOCADDMULTI) \
       X(SIOCDELMULTI) \
       X(SIOCGIFMTU) \
       X(SIOCSIFMTU) \
       X(SIOCGIFPHYS) \
       X(SIOCSIFPHYS) \
       X(SIOCSIFMEDIA) \
       X(SIOCGIFXMEDIA) \
       X(SIOCSIFGENERIC) \
       X(SIOCGIFGENERIC) \
       X(SIOCRSLVMULTI) \
       X(SIOCSIFLLADDR) \
       X(SIOCGIFSTATUS) \
       X(SIOCSIFPHYADDR) \
       X(SIOCGIFPSRCADDR) \
       X(SIOCGIFPDSTADDR) \
       X(SIOCDIFPHYADDR) \
       X(SIOCGIFDEVMTU) \
       X(SIOCSIFALTMTU) \
       X(SIOCGIFALTMTU) \
       X(SIOCSIFBOND) \
       X(SIOCGIFBOND) \
       X(SIOCPROTOATTACH) \
       X(SIOCPROTODETACH) \
       X(SIOCSIFCAP) \
       X(SIOCGIFCAP) \
       X(SIOCSIFMANAGEMENT) \
       X(SIOCSATTACHPROTONULL) \
       X(SIOCIFCREATE) \
       X(SIOCIFDESTROY) \
       X(SIOCIFCREATE2) \
       X(SIOCGDRVSPEC) \
       X(SIOCSDRVSPEC) \
       X(SIOCSIFVLAN) \
       X(SIOCGIFVLAN) \
       X(SIOCIFGCLONERS) \
       X(SIOCGIFASYNCMAP) \
       X(SIOCSIFASYNCMAP) \
       X(SIOCSIFKPI) \
       X(SIOCGIFKPI) \
       X(SIOCGIFWAKEFLAGS) \
       X(SIOCGIFGETRTREFCNT) \
       X(SIOCGIFLINKQUALITYMETRIC) \
       X(SIOCSIFLINKQUALITYMETRIC) \
       X(SIOCSIFOPPORTUNISTIC) \
       X(SIOCGIFOPPORTUNISTIC) \
       X(SIOCGETROUTERMODE) \
       X(SIOCSETROUTERMODE) \
       X(SIOCGIFEFLAGS) \
       X(SIOCSIFDESC) \
       X(SIOCGIFDESC) \
       X(SIOCSIFLINKPARAMS) \
       X(SIOCGIFLINKPARAMS) \
       X(SIOCGIFQUEUESTATS) \
       X(SIOCSIFTHROTTLE) \
       X(SIOCGIFTHROTTLE) \
       X(SIOCGASSOCIDS) \
       X(SIOCGCONNIDS) \
       X(SIOCGCONNINFO) \
       X(SIOCSCONNORDER) \
       X(SIOCGCONNORDER) \
       X(SIOCSIFLOG) \
       X(SIOCGIFLOG) \
       X(SIOCGIFDELEGATE) \
       X(SIOCGIFLLADDR) \
       X(SIOCGIFTYPE) \
       X(SIOCGIFEXPENSIVE) \
       X(SIOCSIFEXPENSIVE) \
       X(SIOCGIF2KCL) \
       X(SIOCSIF2KCL) \
       X(SIOCGSTARTDELAY) \
       X(SIOCAIFAGENTID) \
       X(SIOCDIFAGENTID) \
       X(SIOCGIFAGENTIDS) \
       X(SIOCGIFAGENTDATA) \
       X(SIOCSIFINTERFACESTATE) \
       X(SIOCGIFINTERFACESTATE) \
       X(SIOCSIFPROBECONNECTIVITY) \
       X(SIOCGIFPROBECONNECTIVITY) \
       X(SIOCGIFFUNCTIONALTYPE) \
       X(SIOCSIFPEEREGRESSFUNCTIONALTYPE) \
       X(SIOCSIFNETSIGNATURE) \
       X(SIOCGIFNETSIGNATURE) \
       X(SIOCSIFNETWORKID) \
       X(SIOCGECNMODE) \
       X(SIOCSECNMODE) \
       X(SIOCSIFORDER) \
       X(SIOCGIFORDER) \
       X(SIOCSQOSMARKINGMODE) \
       X(SIOCSQOSMARKINGENABLED) \
       X(SIOCGQOSMARKINGMODE) \
       X(SIOCGQOSMARKINGENABLED) \
       X(SIOCSIFTIMESTAMPENABLE) \
       X(SIOCSIFTIMESTAMPDISABLE) \
       X(SIOCGIFTIMESTAMPENABLED) \
       X(SIOCSIFDISABLEOUTPUT) \
       X(SIOCSIFSUBFAMILY) \
       X(SIOCGIFAGENTLIST) \
       X(SIOCSIFLOWINTERNET) \
       X(SIOCGIFLOWINTERNET) \
       X(SIOCGIFNAT64PREFIX) \
       X(SIOCSIFNAT64PREFIX) \
       X(SIOCGIFCLAT46ADDR) \
       X(SIOCGIFNEXUS) \
       X(SIOCGIFPROTOLIST) \
       X(SIOCGIFTCPKAOMAX) \
       X(SIOCGIFLOWPOWER) \
       X(SIOCSIFLOWPOWER) \
       X(SIOCGIFMPKLOG) \
       X(SIOCSIFMPKLOG) \
       X(SIOCGIFCONSTRAINED) \
       X(SIOCSIFCONSTRAINED) \
       X(SIOCGIFXFLAGS) \
       X(SIOCGIFNOACKPRIO) \
       X(SIOCSIFNOACKPRIO) \
       X(SIOCSIFMARKWAKEPKT) \
       X(SIOCSIFNOTRAFFICSHAPING) \
       X(SIOCGIFNOTRAFFICSHAPING) \
       X(SIOCGIFULTRACONSTRAINED) \
       X(SIOCSIFULTRACONSTRAINED) \
       X(SIOCSIFDIRECTLINK) \
       X(SIOCGIFDIRECTLINK) \
       X(SIOCSIFISVPN) \
       X(SIOCSIFDELAYWAKEPKTEVENT) \
       X(SIOCGIFDELAYWAKEPKTEVENT)


#endif /* ioc_str_h */
