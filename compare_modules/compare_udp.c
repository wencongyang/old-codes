#include <linux/kernel.h>
#include <linux/udp.h>

#include "compare.h"

static void debug_print_udp(void *data)
{
	struct udphdr *udp = data;
	unsigned short src_port, dst_port;

	src_port = htons(udp->source);
	dst_port = htons(udp->dest);
	pr_debug("HA_compare:[UDP] src=%u, dst=%u\n", src_port, dst_port);
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
