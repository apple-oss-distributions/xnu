/*
 * Copyright (c) 2012-2024 Apple Inc. All rights reserved.
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

#include <kern/debug.h>

#if !NETWORKING

#define STUB(name)                                                      \
	int name(void);                                                 \
	int name(void)                                                  \
	{                                                               \
	        panic("stub called in a config with no networking");    \
	        return (0);                                             \
	}

STUB(bpf_attach);
STUB(bpf_tap_in);
STUB(bpf_tap_out);
STUB(bpfattach);
#if !SKYWALK
STUB(bpf_tap_packet_in);
STUB(bpf_tap_packet_out);
#endif /* SKYWALK */
STUB(ctl_deregister);
STUB(ctl_enqueuedata);
STUB(ctl_enqueuembuf);
STUB(ctl_enqueuembuf_list);
STUB(ctl_getenqueuespace);
STUB(ctl_register);
STUB(ether_add_proto);
STUB(ether_check_multi);
STUB(ether_del_proto);
STUB(ether_demux);
STUB(ether_frameout);
STUB(ether_ioctl);
STUB(fifo_advlock);
STUB(fifo_close);
STUB(fifo_inactive);
STUB(fifo_ioctl);
STUB(fifo_lookup);
STUB(fifo_open);
STUB(fifo_pathconf);
STUB(fifo_read);
STUB(fifo_select);
STUB(fifo_write);
STUB(ifaddr_address);
STUB(ifaddr_address_family);
STUB(ifaddr_dstaddress);
STUB(ifaddr_findbestforaddr);
STUB(ifaddr_ifnet);
STUB(ifaddr_netmask);
STUB(ifaddr_reference);
STUB(ifaddr_release);
STUB(ifaddr_withaddr);
STUB(ifaddr_withdstaddr);
STUB(ifaddr_withnet);
STUB(ifaddr_withroute);
STUB(iflt_attach);
STUB(iflt_detach);
STUB(ifmaddr_address);
STUB(ifmaddr_ifnet);
STUB(ifmaddr_lladdress);
STUB(ifmaddr_reference);
STUB(ifmaddr_release);
STUB(ifnet_add_multicast);
STUB(ifnet_addrlen);
STUB(ifnet_allocate);
STUB(ifnet_allocate_internal);
STUB(ifnet_attach);
STUB(ifnet_attach_protocol);
STUB(ifnet_baudrate);
STUB(ifnet_capabilities_enabled);
STUB(ifnet_capabilities_supported);
STUB(ifnet_detach);
STUB(ifnet_detach_protocol);
STUB(ifnet_eflags);
STUB(ifnet_event);
STUB(ifnet_family);
STUB(ifnet_subfamily);
STUB(ifnet_find_by_name);
STUB(ifnet_flags);
STUB(ifnet_free_address_list);
STUB(ifnet_free_multicast_list);
STUB(ifnet_get_address_list);
STUB(ifnet_get_address_list_family);
STUB(ifnet_get_link_mib_data);
STUB(ifnet_get_link_mib_data_length);
STUB(ifnet_get_multicast_list);
STUB(ifnet_get_service_class_sndq_len);
STUB(ifnet_get_tso_mtu);
STUB(ifnet_get_wake_flags);
STUB(ifnet_hdrlen);
STUB(ifnet_index);
STUB(ifnet_input);
STUB(ifnet_interface_family_find);
STUB(ifnet_ioctl);
STUB(ifnet_lastchange);
STUB(ifnet_list_free);
STUB(ifnet_list_get);
STUB(ifnet_lladdr);
STUB(ifnet_lladdr_copy_bytes);
STUB(ifnet_llbroadcast_copy_bytes);
STUB(ifnet_metric);
STUB(ifnet_mtu);
STUB(ifnet_name);
STUB(ifnet_offload);
STUB(ifnet_output);
STUB(ifnet_output_raw);
STUB(ifnet_reference);
STUB(ifnet_release);
STUB(ifnet_remove_multicast);
STUB(ifnet_resolve_multicast);
STUB(ifnet_set_addrlen);
STUB(ifnet_set_baudrate);
STUB(ifnet_set_capabilities_enabled);
STUB(ifnet_set_capabilities_supported);
STUB(ifnet_set_delegate);
STUB(ifnet_set_eflags);
STUB(ifnet_set_flags);
STUB(ifnet_set_hdrlen);
STUB(ifnet_set_link_mib_data);
STUB(ifnet_set_lladdr);
STUB(ifnet_set_metric);
STUB(ifnet_set_mtu);
STUB(ifnet_set_offload);
STUB(ifnet_set_offload_enabled);
STUB(ifnet_set_promiscuous);
STUB(ifnet_set_stat);
STUB(ifnet_set_tso_mtu);
STUB(ifnet_set_wake_flags);
STUB(ifnet_softc);
STUB(ifnet_stat);
STUB(ifnet_stat_increment);
STUB(ifnet_stat_increment_in);
STUB(ifnet_stat_increment_out);
STUB(ifnet_touch_lastchange);
STUB(ifnet_type);
STUB(ifnet_unit);
STUB(in_cksum);
STUB(inet_arp_handle_input);
STUB(inet_arp_init_ifaddr);
STUB(inet_arp_lookup);
STUB(ipf_addv4);
STUB(ipf_addv6);
STUB(ipf_inject_input);
STUB(ipf_inject_output);
STUB(ipf_remove);
STUB(kev_msg_post);
STUB(kev_vendor_code_find);
STUB(mbuf_adj);
STUB(mbuf_adjustlen);
STUB(mbuf_align_32);
STUB(mbuf_alloccluster);
STUB(mbuf_allocpacket);
STUB(mbuf_allocpacket_list);
STUB(mbuf_attachcluster);
STUB(mbuf_clear_csum_performed);
STUB(mbuf_clear_csum_requested);
STUB(mbuf_clear_vlan_tag);
STUB(mbuf_concatenate);
STUB(mbuf_copy_pkthdr);
STUB(mbuf_copyback);
STUB(mbuf_copydata);
STUB(mbuf_copym);
STUB(mbuf_data);
STUB(mbuf_data_to_physical);
STUB(mbuf_datastart);
STUB(mbuf_dup);
STUB(mbuf_flags);
STUB(mbuf_free);
STUB(mbuf_freecluster);
STUB(mbuf_freem);
STUB(mbuf_freem_list);
STUB(mbuf_get);
STUB(mbuf_get_csum_performed);
STUB(mbuf_get_csum_requested);
STUB(mbuf_get_mhlen);
STUB(mbuf_get_minclsize);
STUB(mbuf_get_mlen);
STUB(mbuf_get_traffic_class);
STUB(mbuf_get_tso_requested);
STUB(mbuf_get_gso_info);
STUB(mbuf_set_gso_info);
STUB(mbuf_get_lro_info);
STUB(mbuf_set_lro_info);
STUB(mbuf_get_vlan_tag);
STUB(mbuf_getcluster);
STUB(mbuf_gethdr);
STUB(mbuf_getpacket);
STUB(mbuf_inbound_modified);
STUB(mbuf_inet_cksum);
STUB(mbuf_is_traffic_class_privileged);
STUB(mbuf_leadingspace);
STUB(mbuf_len);
STUB(mbuf_maxlen);
STUB(mbuf_mclget);
STUB(mbuf_mclhasreference);
STUB(mbuf_next);
STUB(mbuf_nextpkt);
STUB(mbuf_outbound_finalize);
STUB(mbuf_pkthdr_adjustlen);
STUB(mbuf_pkthdr_header);
STUB(mbuf_pkthdr_len);
STUB(mbuf_pkthdr_rcvif);
STUB(mbuf_pkthdr_setheader);
STUB(mbuf_pkthdr_setlen);
STUB(mbuf_pkthdr_setrcvif);
STUB(mbuf_prepend);
STUB(mbuf_pulldown);
STUB(mbuf_pullup);
STUB(mbuf_set_csum_performed);
STUB(mbuf_set_csum_requested);
STUB(mbuf_set_traffic_class);
STUB(mbuf_set_vlan_tag);
STUB(mbuf_setdata);
STUB(mbuf_setflags);
STUB(mbuf_setflags_mask);
STUB(mbuf_setlen);
STUB(mbuf_setnext);
STUB(mbuf_setnextpkt);
STUB(mbuf_settype);
STUB(mbuf_split);
STUB(mbuf_stats);
STUB(mbuf_tag_allocate);
STUB(mbuf_tag_find);
STUB(mbuf_tag_free);
STUB(mbuf_tag_id_find);
STUB(mbuf_add_drvaux);
STUB(mbuf_find_drvaux);
STUB(mbuf_del_drvaux);
STUB(mbuf_trailingspace);
STUB(mbuf_type);
STUB(mbuf_get_flowid);
STUB(mbuf_set_flowid);
STUB(mbuf_get_timestamp);
STUB(mbuf_set_timestamp);
STUB(mbuf_get_tx_compl_data);
STUB(mbuf_set_tx_compl_data);
STUB(mbuf_get_status);
STUB(mbuf_set_status);
STUB(mbuf_get_timestamp_requested);
STUB(mbuf_set_timestamp_requested);
STUB(mbuf_register_tx_compl_callback);
STUB(mbuf_unregister_tx_compl_callback);
STUB(mbuf_get_keepalive_flag);
STUB(mbuf_set_keepalive_flag);
STUB(mbuf_get_wake_packet_flag);
STUB(mbuf_set_wake_packet_flag);
STUB(net_init_add);
STUB(proto_inject);
STUB(proto_input);
STUB(proto_register_plumber);
STUB(proto_unregister_plumber);
STUB(sflt_attach);
STUB(sflt_detach);
STUB(sflt_register);
STUB(sflt_unregister);
STUB(sock_accept);
STUB(sock_bind);
STUB(sock_close);
STUB(sock_connect);
STUB(sock_connectwait);
STUB(sock_getpeername);
STUB(sock_getsockname);
STUB(sock_getsockopt);
STUB(sock_gettype);
STUB(sock_inject_data_in);
STUB(sock_inject_data_out);
STUB(sock_ioctl);
STUB(sock_isconnected);
STUB(sock_isnonblocking);
STUB(sock_listen);
STUB(sock_nointerrupt);
STUB(sock_receive);
STUB(sock_receivembuf);
STUB(sock_send);
STUB(sock_sendmbuf);
STUB(sock_sendmbuf_can_wait);
STUB(sock_setpriv);
STUB(sock_setsockopt);
STUB(sock_shutdown);
STUB(sock_socket);
STUB(sockopt_copyin);
STUB(sockopt_copyout);
STUB(sockopt_direction);
STUB(sockopt_level);
STUB(sockopt_name);
STUB(sockopt_valsize);
STUB(kev_post_msg);
STUB(kev_post_msg_nowait);
STUB(ctl_id_by_name);
STUB(ctl_name_by_id);
STUB(ifnet_allocate_extended);
STUB(ifnet_bandwidths);
STUB(ifnet_clone_attach);
STUB(ifnet_clone_detach);
STUB(ifnet_dequeue);
STUB(ifnet_dequeue_multi);
STUB(ifnet_dequeue_multi_bytes);
STUB(ifnet_dequeue_service_class);
STUB(ifnet_dequeue_service_class_multi);
STUB(ifnet_enqueue);
STUB(ifnet_get_delegate);
STUB(ifnet_get_inuse_address_list);
STUB(ifnet_get_local_ports);
STUB(ifnet_get_local_ports_extended);
STUB(ifnet_get_rcvq_maxlen);
STUB(ifnet_get_sndq_len);
STUB(ifnet_get_sndq_maxlen);
STUB(ifnet_idle_flags);
STUB(ifnet_inet6_defrouter_llreachinfo);
STUB(ifnet_inet_defrouter_llreachinfo);
STUB(ifnet_input_extended);
STUB(ifnet_latencies);
STUB(ifnet_link_quality);
STUB(ifnet_notice_master_elected);
STUB(ifnet_notice_primary_elected);
STUB(ifnet_notice_node_absence);
STUB(ifnet_notice_node_presence);
STUB(ifnet_notice_node_presence_v2);
STUB(ifnet_poll_params);
STUB(ifnet_purge);
STUB(ifnet_report_issues);
STUB(ifnet_set_bandwidths);
STUB(ifnet_set_idle_flags);
STUB(ifnet_set_latencies);
STUB(ifnet_set_link_quality);
STUB(ifnet_set_output_sched_model);
STUB(ifnet_set_poll_params);
STUB(ifnet_set_rcvq_maxlen);
STUB(ifnet_set_sndq_maxlen);
STUB(ifnet_start);
STUB(ifnet_tx_compl_status);
STUB(ifnet_tx_compl);
STUB(ifnet_flowid);
STUB(ifnet_enable_output);
STUB(ifnet_disable_output);
STUB(ifnet_get_keepalive_offload_frames);
STUB(ifnet_link_status_report);
STUB(ifnet_set_fastlane_capable);
STUB(ifnet_get_fastlane_capable);
STUB(ifnet_get_unsent_bytes);
STUB(ifnet_get_buffer_status);
STUB(ifnet_normalise_unsent_data);
STUB(ifnet_set_low_power_mode);
STUB(ifnet_notify_tcp_keepalive_offload_timeout);
STUB(in6_localaddr);
STUB(in_localaddr);
STUB(in6addr_local);
STUB(inaddr_local);
STUB(inp_clear_INP_INADDR_ANY);
STUB(ip_gre_output);
STUB(m_cat);
STUB(m_free);
STUB(m_freem);
STUB(m_get);
STUB(m_gethdr);
STUB(m_mtod);
STUB(m_prepend_2);
STUB(m_pullup);
STUB(m_split);
STUB(mbuf_get_driver_scratch);
STUB(mbuf_get_unsent_data_bytes);
STUB(mbuf_get_buffer_status);
STUB(mbuf_pkt_new_flow);
STUB(mbuf_last_pkt);
STUB(mbuf_get_priority);
STUB(mbuf_get_service_class);
STUB(mbuf_get_service_class_index);
STUB(mbuf_get_service_class_max_count);
STUB(mbuf_get_traffic_class_index);
STUB(mbuf_get_traffic_class_max_count);
STUB(mbuf_is_service_class_privileged);
STUB(mbuf_pkthdr_aux_flags);
STUB(mcl_to_paddr);
STUB(net_add_domain);
STUB(net_add_domain_old);
STUB(net_add_proto);
STUB(net_add_proto_old);
STUB(net_del_domain);
STUB(net_del_domain_old);
STUB(net_del_proto);
STUB(net_del_proto_old);
STUB(net_domain_contains_hostname);
STUB(pffinddomain);
STUB(pffinddomain_old);
STUB(pffindproto);
STUB(pffindproto_old);
STUB(pru_abort_notsupp);
STUB(pru_accept_notsupp);
STUB(pru_bind_notsupp);
STUB(pru_connect2_notsupp);
STUB(pru_connect_notsupp);
STUB(pru_disconnect_notsupp);
STUB(pru_listen_notsupp);
STUB(pru_peeraddr_notsupp);
STUB(pru_rcvd_notsupp);
STUB(pru_rcvoob_notsupp);
STUB(pru_send_notsupp);
STUB(pru_send_list_notsupp);
STUB(pru_sense_null);
STUB(pru_shutdown_notsupp);
STUB(pru_sockaddr_notsupp);
STUB(pru_sopoll_notsupp);
STUB(sbappendaddr);
STUB(sbappendrecord);
STUB(sbflush);
STUB(sbspace);
STUB(soabort);
STUB(socantrcvmore);
STUB(socantsendmore);
STUB(sock_getlistener);
STUB(sock_gettclassopt);
STUB(sock_release);
STUB(sock_retain);
STUB(sock_settclassopt);
STUB(sock_catchevents);
STUB(sock_setupcall);
STUB(sock_setupcalls);
STUB(sodisconnect);
STUB(sofree);
STUB(sofreelastref);
STUB(soisconnected);
STUB(soisconnecting);
STUB(soisdisconnected);
STUB(soisdisconnecting);
STUB(sonewconn);
STUB(sooptcopyin);
STUB(sooptcopyout);
STUB(sopoll);
STUB(soreceive);
STUB(soreceive_list);
STUB(soreserve);
STUB(sorwakeup);
STUB(sosend);
STUB(sosend_list);
STUB(utun_ctl_disable_crypto_dtls);
STUB(utun_ctl_register_dtls);
STUB(utun_pkt_dtls_input);
STUB(dlil_resolve_multi);
STUB(inet_cksum_simple);
STUB(arp_ip_handle_input);
STUB(arp_ifinit);
STUB(arp_lookup_ip);
STUB(ip_gre_register_input);
STUB(sock_iskernel);
STUB(iflt_attach_internal);
STUB(ipf_addv4_internal);
STUB(ipf_addv6_internal);
STUB(sflt_register_internal);
STUB(sock_accept_internal);
STUB(sock_socket_internal);
STUB(vsock_add_transport);
STUB(vsock_remove_transport);
STUB(vsock_reset_transport);
STUB(vsock_put_message);
#undef STUB

/*
 * Called from vm_pageout.c. Nothing to be done when there's no networking.
 */
void mbuf_drain(boolean_t);
void
mbuf_drain(boolean_t)
{
	return;
}

#endif /* !NETWORKING */
