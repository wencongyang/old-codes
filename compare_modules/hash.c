#include <linux/ip.h>
#include <net/ip.h>

#include "hash.h"
#include "comm.h"
#include "ipv4_fragment.h"

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

#define ip_is_fragment(iph)	(iph->frag_off & htons(IP_MF | IP_OFFSET))

static inline int __proto_ports_offset(int proto)
{
	switch (proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_DCCP:
	case IPPROTO_ESP:	/* SPI */
	case IPPROTO_SCTP:
	case IPPROTO_UDPLITE:
		return 0;
	case IPPROTO_AH:	/* SPI */
		return 4;
	default:
		return -EINVAL;
	}
}

/*
 * return value:
 *   -1: error
 *    0: normal
 *    1: ip fragment
 */
static int skb_flow_dissect(const struct sk_buff *skb,
			    struct flow_keys *flow,
			    bool check_fragment)
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
			return -1;

		if (check_fragment && ip_is_fragment(iph))
			return 1;
		else if (iph->protocol != 0)
			ip_proto = iph->protocol;
		else
			return -1;
		iph_to_flow_copy_addrs(flow, iph);
		nhoff += iph->ihl * 4;
		break;
	}
	default:
		return 0;
	}

	flow->ip_proto = ip_proto;
	poff = __proto_ports_offset(ip_proto);
	if (poff >= 0) {
		__be32 *ports, _ports;

		nhoff += poff;
		/* poff is 0 or 4, so the port is stored in fragment 0 */
		ports = skb_header_pointer(skb, nhoff, sizeof(_ports), &_ports);
		if (ports)
			flow->ports = *ports;
		else
			return -1;
	}

	flow->thoff = (u16) nhoff;

	return 0;
}

static struct hash_value *alloc_hash_value(struct flow_keys *key)
{
	struct hash_value *value;

	value = kzalloc(sizeof(*value), GFP_ATOMIC);
	if (!value)
		return NULL;

	value->key = *key;
	INIT_LIST_HEAD(&value->list);
	INIT_LIST_HEAD(&value->compare_list);
	skb_queue_head_init(&value->master_queue);
	skb_queue_head_init(&value->slaver_queue);
	value->head = NULL;

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

static void free_fragments(struct sk_buff *head, struct sk_buff *except)
{
	struct sk_buff *skb = head;
	struct sk_buff *next;

	do {
		if (skb == head)
			next = skb_shinfo(skb)->frag_list;
		else
			next = skb->next;

		if (skb != except )
			kfree_skb(skb);
		else if (skb == head)
			skb_shinfo(skb)->frag_list = NULL;
		else
			skb->next = NULL;

		skb = next;
	} while (skb != NULL);
}

struct hash_value *insert(struct hash_head *h, struct sk_buff *skb, uint32_t flags)
{
	struct flow_keys key;
	struct hash_value *value;
	struct sk_buff *head = NULL;
	uint32_t hash;
	int i;
	int ret;

	FRAG_CB(skb)->flags = 0;
	ret = skb_flow_dissect(skb, &key, true);
	if (ret < 0)
		return NULL;
	else if (ret > 0) {
		struct ip_frags *ip_frags;

		if (flags & IS_MASTER)
			ip_frags = &h->master_data->ipv4_frags;
		else
			ip_frags = &h->slaver_data->ipv4_frags;
		head = ipv4_defrag(skb, ip_frags);
		if (IS_ERR(head)) {
			if (PTR_ERR(head) != -EINPROGRESS)
				return NULL;

			return ERR_PTR(-EINPROGRESS);
		}

		ret = skb_flow_dissect(head, &key, false);
		if (ret < 0) {
			free_fragments(head, skb);
			return NULL;
		}
		FRAG_CB(head)->flags |= IS_FRAGMENT;
	}

	hash = jhash(&key, sizeof(key), JHASH_INITVAL);

	i = hash % HASH_NR;
	value = get_hash_value(&h->entry[i], &key);
	if (unlikely(!value)) {
		value = alloc_hash_value(&key);
		if (unlikely(!value)) {
			if (head)
				free_fragments(head, skb);
			return NULL;
		}

		value->head = h;
		list_add_tail(&value->list, &h->entry[i]);
	}

	if (flags & IS_MASTER)
		skb_queue_tail(&value->master_queue, head ? head : skb);
	else
		skb_queue_tail(&value->slaver_queue, head ? head : skb);

	return value;
}
