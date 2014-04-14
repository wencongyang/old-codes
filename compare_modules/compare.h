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

enum {
	state_comparing,
	state_incheckpoint,
	state_failover,
};
extern uint32_t state;

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

/* It is protected by RCU, so don't sleep in all callbacks */
struct compare_ops {
	uint32_t (*compare)(struct compare_info *m_cinfo,
			    struct compare_info *s_cinfo);
	uint32_t (*compare_one_packet)(struct compare_info *m_cinfo,
				       struct compare_info *s_cinfo);
	uint32_t (*compare_fragment)(struct compare_info *m_cinfo,
				     struct compare_info *s_cinfo);
	uint32_t (*compare_one_fragment)(struct compare_info *m_cinfo,
					 struct compare_info *s_cinfo);
	void (*update_info)(void *info, void *data, uint32_t len, struct sk_buff *skb);
	void (*update_packet)(struct compare_info *m_cinfo,
			      struct compare_info *s_cinfo,
			      uint32_t ret);
	void (*flush_packets)(void *info);
	void (*debug_print)(const struct compare_info *cinfo, const void *data);
};

typedef struct compare_ops compare_ops_t;

#define		BYPASS_MASTER		0x01
#define		DROP_SLAVER		0x02
#define		SAME_PACKET		(BYPASS_MASTER | DROP_SLAVER)
#define		CHECKPOINT		0x80000000
#define		UPDATE_COMPARE_INFO	0x40000000
#define		UPDATE_MASTER_PACKET	0x20000000
#define		IGNORE_LEN		0x10000000

extern uint32_t compare_other_packet(void *m_data, void *s_data, int length);
extern wait_queue_head_t queue;

/* compare device */
extern int colo_dev_init(void);
extern void colo_dev_fini(void);

/* arp */
extern uint32_t arp_compare_packet(struct compare_info *m_cinfo,
				   struct compare_info *s_cinfo);
extern uint32_t arp_compare_one_packet(struct compare_info *m_cinfo,
				       struct compare_info *s_cinfo);
extern void debug_print_arp(const struct arphdr *arp);

/* ipv4 */
extern uint32_t ipv4_compare_packet(struct compare_info *m_cinfo,
				    struct compare_info *s_cinfo);
extern void ipv4_update_compare_info(void *info, struct iphdr *ip,
				   struct sk_buff *skb);
extern void ipv4_flush_packets(void *info, uint8_t protocol);

extern int register_compare_ops(compare_ops_t *ops, unsigned short protocol);
extern int unregister_compare_ops(compare_ops_t *ops, unsigned short protocol);
extern uint32_t ipv4_transport_compare_fragment(struct sk_buff *m_head,
						struct sk_buff *s_head,
						int m_off, int s_off, int len);
extern uint32_t ipv4_compare_one_packet(struct compare_info *m_cinfo,
					struct compare_info *s_cinfo);

#endif
