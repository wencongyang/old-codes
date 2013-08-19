#include "hash.h"
#include <linux/ip.h>
#include <net/ip.h>

void hash_init(struct hash_head *h)
{
	int i;

	memset(h, 0, sizeof(*h));
	for (i = 0; i < HASH_NR; i++)
		INIT_LIST_HEAD(&h->entry[i]);

	INIT_LIST_HEAD(&h->list);
	skb_queue_head_init(&h->wait_for_release);
}

/* copied from kernel, old kernel doesn't have the API skb_flow_dissect() */

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

static struct hash_value *alloc_hash_value(struct flow_keys *key)
{
	struct hash_value *value;

	value = kmalloc(sizeof(*value), GFP_ATOMIC);
	if (!value)
		return NULL;

	value->key = *key;
	INIT_LIST_HEAD(&value->list);
	INIT_LIST_HEAD(&value->compare_list);
	skb_queue_head_init(&value->master_queue);
	skb_queue_head_init(&value->slaver_queue);
	value->head = NULL;
	value->m_last_seq = value->s_last_seq = 0;

	return value;
}

static struct hash_value *get_hash_value(struct list_head *head, struct flow_keys *key)
{
	struct hash_value *value;

	list_for_each_entry(value, head, list) {
		if (value->key.src == key->src &&
		    value->key.dst == key->dst &&
		    value->key.ports == key->ports &&
		    value->key.ip_proto == key->ip_proto)
			return value;
	}

	return NULL;
}

struct hash_value *insert(struct hash_head *h, struct sk_buff *skb, uint32_t flags)
{
	struct flow_keys key;
	struct hash_value *value;
	uint32_t hash;
	int i;

	skb_flow_dissect(skb, &key);
	hash = jhash(&key, sizeof(key), JHASH_INITVAL);

	i = hash % HASH_NR;
	value = get_hash_value(&h->entry[i], &key);
	if (unlikely(!value)) {
		value = alloc_hash_value(&key);
		if (unlikely(!value))
			return NULL;

		value->head = h;
		list_add_tail(&value->list, &h->entry[i]);
	}

	if (flags & IS_MASTER)
		skb_queue_tail(&value->master_queue, skb);
	else
		skb_queue_tail(&value->slaver_queue, skb);

	return value;
}
