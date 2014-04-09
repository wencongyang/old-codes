/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  Compare udp packets from master and slave.
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/kernel.h>

#include "compare.h"

static void debug_print_udp(const struct compare_info *info, const void *data)
{
	const struct udphdr *udp = data;
	unsigned short src_port, dst_port;

	src_port = ntohs(udp->source);
	dst_port = ntohs(udp->dest);
	pr_warn("HA_compare:[UDP] src=%u, dst=%u\n", src_port, dst_port);
}

static compare_ops_t udp_ops = {
	.debug_print = debug_print_udp,
};

void compare_udp_init(void)
{
	register_compare_ops(&udp_ops, IPPROTO_UDP);
}

void compare_udp_fini(void)
{
	unregister_compare_ops(&udp_ops, IPPROTO_UDP);
}
