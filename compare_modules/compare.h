/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#ifndef COMPARE_H
#define COMPARE_H

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

struct compare_info {
	struct sk_buff *skb;
	struct ethhdr *eth;
	union {
		void *packet;
		struct iphdr *ip;
		struct arphdr *arp;
	};
	union {
		void *ip_data;
		struct tcphdr *tcp;
		struct udphdr *udp;
	};
	union {
		void *transport_data;
		void *tcp_data;
		void *udp_data;
	};
	unsigned int length;

	/* length: 32*4 bytes */
	void *private_data;
};

#define		BYPASS_MASTER		0x01
#define		DROP_SLAVER		0x02
#define		SAME_PACKET		(BYPASS_MASTER | DROP_SLAVER)
#define		CHECKPOINT		0x80000000
#define		UPDATE_COMPARE_INFO	0x40000000
#define		UPDATE_MASTER_PACKET	0x20000000
#define		IGNORE_LEN		0x10000000

extern uint32_t default_compare_data(void *m_data, void *s_data, int length);
extern wait_queue_head_t queue;

/* arp */
extern uint32_t arp_compare_packet(struct compare_info *m_cinfo,
				   struct compare_info *s_cinfo);
extern uint32_t arp_compare_one_packet(struct compare_info *m_cinfo,
				       struct compare_info *s_cinfo);

/* ipv4 */
extern uint32_t ipv4_compare_packet(struct compare_info *m_cinfo,
				    struct compare_info *s_cinfo);
extern void ipv4_update_compare_info(void *info, struct iphdr *ip,
				   struct sk_buff *skb);
extern void ipv4_flush_packets(void *info, uint8_t protocol);
extern uint32_t ipv4_compare_one_packet(struct compare_info *m_cinfo,
					struct compare_info *s_cinfo);

#endif
