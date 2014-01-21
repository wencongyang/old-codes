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
