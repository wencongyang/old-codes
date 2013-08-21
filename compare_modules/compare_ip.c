#include <linux/module.h>
#include <linux/kernel.h>
#include <net/protocol.h>

#include "compare.h"

const compare_ops_t *compare_inet_ops[MAX_INET_PROTOS];

int register_compare_ops(compare_ops_t *ops, unsigned short protocol)
{
	return !cmpxchg((const compare_ops_t **)&compare_inet_ops[protocol],
			NULL, ops) ? 0 : -1;
}

int unregister_compare_ops(compare_ops_t *ops, unsigned short protocol)
{
	return cmpxchg((const compare_ops_t **)&compare_inet_ops[protocol],
		       ops, NULL) == ops ? 0 : -1;
}
EXPORT_SYMBOL(register_compare_ops);
EXPORT_SYMBOL(unregister_compare_ops);

static void debug_print_ip(const struct iphdr *ip)
{
	unsigned short len = htons(ip->tot_len);
	unsigned short id = htons(ip->id);
	unsigned char protocol = ip->protocol;
	void *data = (char *)ip + ip->ihl * 4;
	const compare_ops_t * ops = compare_inet_ops[protocol];

	pr_debug("HA_compare:[IP]len = %u, id= %u.\n", len, id);

	if (ops && ops->debug_print)
		ops->debug_print(data);
	else
		pr_debug("HA_compare: unkown protocol: %u\n", protocol);
}

static void print_debuginfo(struct compare_info *m, struct compare_info *s)
{
	pr_debug("HA_compare: same=%u, last_id=%u\n", same_count, last_id);
	pr_debug("HA_compare: Master pkt:\n");
	debug_print_ip(m->ip);
	pr_debug("HA_compare: Slaver pkt:\n");
	debug_print_ip(s->ip);
}

int compare_ip_packet(struct compare_info *m, struct compare_info *s)
{
	int ret;
	const compare_ops_t *ops;

	if (unlikely(m->ip->ihl * 4 > m->length)) {
		pr_warn("HA_compare: master iphdr is corrupted\n");
		return 0;
	}

	if (unlikely(s->ip->ihl * 4 > s->length)) {
		pr_warn("HA_compare: slaver iphdr is corrupted\n");
		return 0;
	}

#define compare_elem(elem)						\
	if (unlikely(m->ip->elem != s->ip->elem)) {			\
		pr_warn("HA_compare: iphdr's %s is different\n",	\
			#elem);\
		pr_warn("HA_compare: master %s: %u\n", #elem,		\
			m->ip->elem);					\
		pr_warn("HA_compare: slaver %s: %u\n", #elem,		\
			s->ip->elem);					\
		print_debuginfo(m, s);					\
		return 0;						\
	}

	compare_elem(version);
	compare_elem(ihl);
	compare_elem(protocol);
	compare_elem(saddr);
	compare_elem(daddr);

	/* IP options */
	if (memcmp((char *)m->ip+20, (char*)s->ip+20, m->ip->ihl*4 - 20)) {
		pr_warn("HA_compare: iphdr option is different\n");
		print_debuginfo(m, s);
		return 0;
	}

	m->ip_data = (char *)m->ip + m->ip->ihl * 4;
	if (m->length <= htons(m->ip->tot_len))
		m->length -= m->ip->ihl * 4;
	else
		m->length = htons(m->ip->tot_len) - m->ip->ihl * 4;
	s->ip_data = (char *)s->ip + s->ip->ihl * 4;
	if (s->length <= htons(s->ip->tot_len))
		s->length -= s->ip->ihl * 4;
	else
		s->length = htons(s->ip->tot_len) - s->ip->ihl * 4;

	ops = compare_inet_ops[m->ip->protocol];
	if (ops && ops->compare) {
		ret = ops->compare(m, s);
	} else {
//		pr_info("unknown protocol: %u", ntohs(master->protocol));
		if (m->length != s->length) {
			pr_warn("HA_compare: the length of packet is different\n");
			print_debuginfo(m, s);
			return 0;
		}
		ret = compare_other_packet(m->ip_data, s->ip_data, m->length);
	}
	if (!ret) {
		print_debuginfo(m, s);
		return 0;
	}

	if (ret != SAME_PACKET)
		return ret;

	compare_elem(tos);
	compare_elem(tot_len);
	compare_elem(frag_off);
	compare_elem(ttl);
	if (!ignore_id) {
		compare_elem(id);
		compare_elem(check);
	}

#undef compare_elem

	last_id = htons(m->ip->id);

	return SAME_PACKET;
}

void ip_update_compare_info(void *info, struct iphdr *ip)
{
	unsigned char protocol;
	void *data;
	uint32_t len;

	protocol = ip->protocol;
	data = (char *)ip + ip->ihl * 4;
	len = ip->tot_len - ip->ihl * 4;
	if (compare_inet_ops[protocol] &&
	    compare_inet_ops[protocol]->update_info)
		compare_inet_ops[protocol]->update_info(info, data, len);
}
