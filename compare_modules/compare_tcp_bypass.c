/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Bypass tcp packets
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/module.h>
#include <linux/kernel.h>

#include "compare.h"
#include "compare_ipv4.h"

static uint32_t tcp_compare_packet(struct compare_info *m_cinfo,
				   struct compare_info *s_cinfo)
{
	return SAME_PACKET;
}

static uint32_t tcp_compare_one_packet(struct compare_info *m_cinfo,
				       struct compare_info *s_cinfo)
{
	uint32_t ret = 0;

	if (m_cinfo->skb)
		ret |= BYPASS_MASTER;
	if (s_cinfo->skb)
		ret |= DROP_SLAVER;
	return ret;
}

static ipv4_compare_ops_t tcp_ops = {
	.compare = tcp_compare_packet,
	.compare_one_packet = tcp_compare_one_packet,
};

static int __init compare_tcp_init(void)
{
	return register_ipv4_compare_ops(&tcp_ops, IPPROTO_TCP);
}

static void __exit compare_tcp_fini(void)
{
	unregister_ipv4_compare_ops(&tcp_ops, IPPROTO_TCP);
}

module_init(compare_tcp_init);
module_exit(compare_tcp_fini);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
