#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/rcupdate.h>
#include <net/protocol.h>
#include <net/ip.h>

#include "compare.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

bool ignore_id = 1;
module_param(ignore_id, bool, 0644);
MODULE_PARM_DESC(ignore_id, "bypass id difference");

const compare_ops_t *compare_inet_ops[MAX_INET_PROTOS];
DEFINE_MUTEX(inet_ops_lock);

int register_compare_ops(compare_ops_t *ops, unsigned short protocol)
{
	mutex_lock(&inet_ops_lock);
	if (compare_inet_ops[protocol]) {
		mutex_unlock(&inet_ops_lock);
		return -1;
	}

	rcu_assign_pointer(compare_inet_ops[protocol], ops);
	mutex_unlock(&inet_ops_lock);

	synchronize_rcu();
	return 0;
}

int unregister_compare_ops(compare_ops_t *ops, unsigned short protocol)
{
	mutex_lock(&inet_ops_lock);
	if (compare_inet_ops[protocol] != ops) {
		mutex_unlock(&inet_ops_lock);
		return -1;
	}

	rcu_assign_pointer(compare_inet_ops[protocol], NULL);
	mutex_unlock(&inet_ops_lock);

	synchronize_rcu();
	return 0;
}
EXPORT_SYMBOL(register_compare_ops);
EXPORT_SYMBOL(unregister_compare_ops);

static void debug_print_ip(const struct compare_info *info, const struct iphdr *ip)
{
	unsigned short len = htons(ip->tot_len);
	unsigned short id = htons(ip->id);
	unsigned char protocol = ip->protocol;
	void *data = (char *)ip + ip->ihl * 4;
	const compare_ops_t * ops;

	pr_warn("HA_compare:[IP]len = %u, id= %u.\n", len, id);

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->debug_print)
		ops->debug_print(info, data);
	else
		pr_warn("HA_compare: unkown protocol: %u\n", protocol);
	rcu_read_unlock();
}

static void print_debuginfo(struct compare_info *m, struct compare_info *s)
{
	pr_warn("HA_compare: same=%u, last_id=%u\n", same_count, last_id);
	pr_warn("HA_compare: Master pkt:\n");
	debug_print_ip(m, m->ip);
	pr_warn("HA_compare: Slaver pkt:\n");
	debug_print_ip(s, s->ip);
}

#define ip_is_fragment(iph)	(iph->frag_off & htons(IP_MF | IP_OFFSET))

static uint32_t compare_ip_fragment(struct compare_info *m, struct compare_info *s)
{
	return ipv4_transport_compare_fragment(m->skb, s->skb, 0, 0, m->length);
}

static inline void set_frag_cb(struct compare_info *info)
{
	FRAG_CB(info->skb)->offset = 0;
	FRAG_CB(info->skb)->len = info->length;
	FRAG_CB(info->skb)->tot_len = info->length;

	/* skb is linear, so it is safe to reset frag_list */
	skb_shinfo(info->skb)->frag_list = NULL;
}

uint32_t compare_ip_packet(struct compare_info *m, struct compare_info *s)
{
	uint32_t ret;
	const compare_ops_t *ops;
	bool m_fragment, s_fragment;

	if (unlikely(m->ip->ihl * 4 > m->length)) {
		pr_warn("HA_compare: master iphdr is corrupted\n");
		return CHECKPOINT;
	}

	if (unlikely(s->ip->ihl * 4 > s->length)) {
		pr_warn("HA_compare: slaver iphdr is corrupted\n");
		return CHECKPOINT;
	}

#define compare_elem(elem)						\
	do {								\
		if (unlikely(m->ip->elem != s->ip->elem)) {		\
			pr_warn("HA_compare: iphdr's %s is different\n",\
				#elem);					\
			pr_warn("HA_compare: master %s: %u\n", #elem,	\
				m->ip->elem);				\
			pr_warn("HA_compare: slaver %s: %u\n", #elem,	\
				s->ip->elem);				\
			print_debuginfo(m, s);				\
			return CHECKPOINT;				\
		}							\
	} while (0)

	compare_elem(version);
	compare_elem(ihl);
	compare_elem(protocol);
	compare_elem(saddr);
	compare_elem(daddr);

	/* IP options */
	if (memcmp((char *)m->ip+20, (char*)s->ip+20, m->ip->ihl*4 - 20)) {
		pr_warn("HA_compare: iphdr option is different\n");
		print_debuginfo(m, s);
		return CHECKPOINT;
	}

	m_fragment = ip_is_fragment(m->ip);
	s_fragment = ip_is_fragment(s->ip);
	m->ip_data = (char *)m->ip + m->ip->ihl * 4;
	if (m_fragment)
		m->length = FRAG_CB(m->skb)->tot_len;
	else if (m->length <= htons(m->ip->tot_len))
		m->length -= m->ip->ihl * 4;
	else
		m->length = htons(m->ip->tot_len) - m->ip->ihl * 4;

	s->ip_data = (char *)s->ip + s->ip->ihl * 4;
	if (s_fragment)
		s->length = FRAG_CB(s->skb)->tot_len;
	else if (s->length <= htons(s->ip->tot_len))
		s->length -= s->ip->ihl * 4;
	else
		s->length = htons(s->ip->tot_len) - s->ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[m->ip->protocol]);
	if (m_fragment || s_fragment) {
		if (ops && ops->compare_fragment) {
			if (!m_fragment)
				set_frag_cb(m);
			if (!s_fragment)
				set_frag_cb(s);
			ret = ops->compare_fragment(m, s);
		} else {
			if (m->length != s->length) {
				pr_warn("HA_compare: the length of packet is different\n");
				print_debuginfo(m, s);
				rcu_read_unlock();
				return CHECKPOINT;
			}
			ret = compare_ip_fragment(m, s);
		}
	} else {
		if (ops && ops->compare) {
			ret = ops->compare(m, s);
		} else {
//			pr_info("unknown protocol: %u", ntohs(master->protocol));
			if (m->length != s->length) {
				pr_warn("HA_compare: the length of packet is different\n");
				print_debuginfo(m, s);
				rcu_read_unlock();
				return CHECKPOINT;
			}
			ret = compare_other_packet(m->ip_data, s->ip_data, m->length);
		}
	}
	rcu_read_unlock();
	if (ret & CHECKPOINT)
		print_debuginfo(m, s);

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

void ip_update_compare_info(void *info, struct iphdr *ip, struct sk_buff *skb)
{
	unsigned char protocol;
	void *data;
	uint32_t len;
	const compare_ops_t *ops;

	protocol = ip->protocol;
	data = (char *)ip + ip->ihl * 4;
	len = ip->tot_len - ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->update_info)
		ops->update_info(info, data, len, skb);
	rcu_read_unlock();
}

uint32_t ipv4_transport_compare_fragment(struct sk_buff *m_head,
				    struct sk_buff *s_head,
				    int m_off, int s_off, int len)
{
	struct sk_buff *m_skb = ipv4_get_skb_by_offset(m_head, m_off);
	struct sk_buff *s_skb = ipv4_get_skb_by_offset(s_head, s_off);
	void *m_data, *s_data;
	int cmp_len, m_len, s_len;
	int ret;

	if (!m_skb || !s_skb)
		return CHECKPOINT;

	if (len <= 0)
		return SAME_PACKET;

	m_len = FRAG_CB(m_skb)->len - (m_off - FRAG_CB(m_skb)->offset);
	s_len = FRAG_CB(s_skb)->len - (s_off - FRAG_CB(s_skb)->offset);
	m_data = ipv4_get_data(m_skb, m_off);
	s_data = ipv4_get_data(s_skb, s_off);

#define NEXT_DATA(skb, head, data, _len, cmp_len)				\
	{									\
		if (_len > cmp_len) {						\
			FRAG_CB(skb)->len -= cmp_len;				\
			data += cmp_len;					\
		} else {							\
			skb = next_skb(skb, head);				\
			if (!skb)						\
				break;						\
			data = ipv4_get_data(skb, FRAG_CB(skb)->offset);	\
			_len = FRAG_CB(skb)->len;				\
		}								\
	}

	do {
		cmp_len = min3(m_len, s_len, len);
		ret = memcmp(m_data, s_data, cmp_len);
		if (ret)
			return CHECKPOINT;

		len -= cmp_len;
		if (len == 0)
			return SAME_PACKET;

		NEXT_DATA(m_skb, m_head, m_data, m_len, cmp_len);
		NEXT_DATA(s_skb, s_head, s_data, s_len, cmp_len);
	} while(len > 0);
#undef NEXT_DATA

	return CHECKPOINT;
}

uint32_t ipv4_compare_one_packet(struct compare_info *m, struct compare_info *s)
{
	struct sk_buff *skb;
	struct compare_info *info = NULL;
	struct compare_info *other_info = NULL;
	uint32_t ret = 0;
	const compare_ops_t *ops;
	bool fragment;

	if (m->skb) {
		info = m;
		other_info = s;
		ret = BYPASS_MASTER;
	} else if (s->skb) {
		info = s;
		other_info = m;
		ret = DROP_SLAVER;
	} else
		BUG();

	skb = info->skb;

	if (unlikely(info->ip->ihl * 4 > info->length)) {
		pr_warn("HA_compare: %s iphdr is corrupted\n",
			m->skb ? "master" : "slaver");
		goto err;
	}

	fragment = ip_is_fragment(info->ip);
	info->ip_data = (char *)info->ip + info->ip->ihl * 4;
	if (fragment)
		info->length = FRAG_CB(info->skb)->tot_len;
	else if (info->length <= htons(info->ip->tot_len))
		info->length -= info->ip->ihl * 4;
	else
		info->length = htons(info->ip->tot_len) - info->ip->ihl * 4;

	/* clear other_info to avoid unexpected errors */
	other_info->ip_data = NULL;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[info->ip->protocol]);
	if (fragment) {
		if (ops && ops->compare_one_fragment) {
			ret = ops->compare_one_fragment(m, s);
		} else {
			rcu_read_unlock();
			goto unsupported;
		}
	} else {
		if (ops && ops->compare_one_packet) {
			ret = ops->compare_one_packet(m, s);
		} else {
			rcu_read_unlock();
			goto unsupported;
		}
	}
	rcu_read_unlock();

err:
	return ret;

unsupported:
	return 0;
}
