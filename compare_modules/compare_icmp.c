#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/icmp.h>

#include "compare.h"

static void debug_print_icmp(const struct compare_info *info, const void *data)
{
	const struct icmphdr *icmp = data;

	pr_warn("HA_compare:[ICMP] code=%u\n", icmp->code);
}

static uint32_t icmp_compare_packet(struct compare_info *m, struct compare_info *s)
{
	return SAME_PACKET;
}

static uint32_t icmp_compare_one_packet(struct compare_info *m, struct compare_info *s)
{
	uint32_t ret = 0;

	if (m->skb)
		ret |= BYPASS_MASTER;
	if (s->skb)
		ret |= DROP_SLAVER;
	return ret;
}

static compare_ops_t icmp_ops = {
	.debug_print = debug_print_icmp,
	.compare = icmp_compare_packet,
	.compare_one_packet = icmp_compare_one_packet,
};

static __init int compare_icmp_init(void)
{
	return register_compare_ops(&icmp_ops, IPPROTO_ICMP);
}

static __exit void compare_icmp_fini(void)
{
	unregister_compare_ops(&icmp_ops, IPPROTO_ICMP);
}

module_init(compare_icmp_init);
module_exit(compare_icmp_fini);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
