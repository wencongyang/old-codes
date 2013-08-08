#include "hash.h"
#include <linux/ip.h>
#include <net/ip.h>

void hash_init(struct hash_head *h)
{
	int i;

	for (i = 0; i < HASH_NR; i++) {
		skb_queue_head_init(&h->e[i].queue);
	}
}

/* copied from kernel, old kernel doesn't have the API skb_flow_dissect() */
struct flow_keys {
	/* (src,dst) must be grouped, in the same way than in IP header */
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	u16 thoff;
	u8 ip_proto;
};

/* copy saddr & daddr, possibly using 64bit load/store
 * Equivalent to :	flow->src = iph->saddr;
 *			flow->dst = iph->daddr;
 */
static void iph_to_flow_copy_addrs(struct flow_keys *flow, const struct iphdr *iph)
{
	BUILD_BUG_ON(offsetof(typeof(*flow), dst) !=
		     offsetof(typeof(*flow), src) + sizeof(flow->src));
	memcpy(&flow->src, &iph->saddr, sizeof(flow->src) + sizeof(flow->dst));
}

bool skb_flow_dissect(const struct sk_buff *skb, struct flow_keys *flow)
{
	int poff, nhoff = skb_network_offset(skb);
	u8 ip_proto;
	__be16 proto = skb->protocol;

	memset(flow, 0, sizeof(*flow));

	switch (proto) {
	case __constant_htons(ETH_P_IP): {
		const struct iphdr *iph;
		struct iphdr _iph;

		iph = skb_header_pointer(skb, nhoff, sizeof(_iph), &_iph);
		if (!iph)
			return false;

		if (ip_is_fragment(iph))
			ip_proto = 0;
		else if (iph->protocol != 0)
			ip_proto = iph->protocol;
		else
			return false;
		iph_to_flow_copy_addrs(flow, iph);
		nhoff += iph->ihl * 4;
		break;
	}
	default:
		return false;
	}

	flow->ip_proto = ip_proto;
	poff = proto_ports_offset(ip_proto);
	if (poff >= 0) {
		__be32 *ports, _ports;

		nhoff += poff;
		ports = skb_header_pointer(skb, nhoff, sizeof(_ports), &_ports);
		if (ports)
			flow->ports = *ports;
	}

	flow->thoff = (u16) nhoff;

	return true;
}


int fetch_key(const struct sk_buff *skb, unsigned short *src, unsigned short *dst)
{
	struct flow_keys keys;

	if (skb_flow_dissect(skb, &keys)) {
		*src = htons(keys.port16[0]);
		*dst = htons(keys.port16[1]);
	} else {
		*src = *dst = 0;
	}

	return 0;
}


int insert(struct hash_head *h, struct sk_buff *skb)
{
	unsigned short src, dst;
	int i;

	fetch_key(skb, &src, &dst);
	i = dst % HASH_NR;
	skb_queue_tail(&h->e[i].queue, skb);

	return i;
}
