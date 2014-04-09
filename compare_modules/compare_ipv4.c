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

/* static */
unsigned short last_id = 0;
unsigned int same_count = 0;

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

static void debug_print_ip(const struct compare_info *cinfo,
			   const struct iphdr *ip)
{
	unsigned short len = ntohs(ip->tot_len);
	unsigned short id = ntohs(ip->id);
	unsigned char protocol = ip->protocol;
	void *data = (char *)ip + ip->ihl * 4;
	const compare_ops_t * ops;

	pr_warn("HA_compare:[IP]len = %u, id= %u.\n", len, id);

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->debug_print)
		ops->debug_print(cinfo, data);
	else
		pr_warn("HA_compare: unknown protocol: %u\n", protocol);
	rcu_read_unlock();
}

static void print_debuginfo(struct compare_info *m_cinfo,
			    struct compare_info *s_cinfo)
{
	pr_warn("HA_compare: same=%u, last_id=%u\n", same_count, last_id);
	pr_warn("HA_compare: Master pkt:\n");
	debug_print_ip(m_cinfo, m_cinfo->ip);
	pr_warn("HA_compare: Slaver pkt:\n");
	debug_print_ip(s_cinfo, s_cinfo->ip);
}

#define ip_is_fragment(iph)	(iph->frag_off & htons(IP_MF | IP_OFFSET))

static uint32_t ipv4_compare_fragment(struct compare_info *m_cinfo,
				      struct compare_info *s_cinfo)
{
	return ipv4_transport_compare_fragment(m_cinfo->skb, s_cinfo->skb, 0, 0,
					       m_cinfo->length);
}

static inline void set_frag_cb(struct compare_info *cinfo)
{
	FRAG_CB(cinfo->skb)->offset = 0;
	FRAG_CB(cinfo->skb)->len = cinfo->length;
	FRAG_CB(cinfo->skb)->tot_len = cinfo->length;

	/* skb is linear, so it is safe to reset frag_list */
	skb_shinfo(cinfo->skb)->frag_list = NULL;
}

static void ipv4_update_packet(struct compare_info *m_cinfo,
			       struct compare_info *s_cinfo,
			       uint8_t protocol)
{
	const compare_ops_t *ops;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->update_packet)
		ops->update_packet(m_cinfo, s_cinfo);
	else
		pr_warn("update_packet is not supported,"
			" but returns UPDATE_MASTER_PACKET\n");
	rcu_read_unlock();
}

static uint32_t
__ipv4_compare_packet(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	uint32_t ret;
	const compare_ops_t *ops;
	bool m_fragment, s_fragment;

	if (unlikely(m_cinfo->ip->ihl * 4 > m_cinfo->length)) {
		pr_warn("HA_compare: master iphdr is corrupted\n");
		return CHECKPOINT;
	}

	if (unlikely(s_cinfo->ip->ihl * 4 > s_cinfo->length)) {
		pr_warn("HA_compare: slaver iphdr is corrupted\n");
		return CHECKPOINT;
	}

#define compare_elem(elem)						\
	do {								\
		if (unlikely(m_cinfo->ip->elem != s_cinfo->ip->elem)) {	\
			pr_warn("HA_compare: iphdr's %s is different\n",\
				#elem);					\
			pr_warn("HA_compare: master %s: %x\n", #elem,	\
				m_cinfo->ip->elem);			\
			pr_warn("HA_compare: slaver %s: %x\n", #elem,	\
				s_cinfo->ip->elem);			\
			print_debuginfo(m_cinfo, s_cinfo);		\
			return CHECKPOINT | UPDATE_COMPARE_INFO;	\
		}							\
	} while (0)

	compare_elem(version);
	compare_elem(ihl);
	compare_elem(protocol);
	compare_elem(saddr);
	compare_elem(daddr);

	/* IP options */
	if (memcmp((char *)m_cinfo->ip + 20, (char*)s_cinfo->ip + 20,
		   m_cinfo->ip->ihl * 4 - 20)) {
		pr_warn("HA_compare: iphdr option is different\n");
		print_debuginfo(m_cinfo, s_cinfo);
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	m_fragment = ip_is_fragment(m_cinfo->ip);
	s_fragment = ip_is_fragment(s_cinfo->ip);
	m_cinfo->ip_data = (char *)m_cinfo->ip + m_cinfo->ip->ihl * 4;
	if (m_fragment)
		m_cinfo->length = FRAG_CB(m_cinfo->skb)->tot_len;
	else if (m_cinfo->length <= ntohs(m_cinfo->ip->tot_len))
		m_cinfo->length -= m_cinfo->ip->ihl * 4;
	else
		m_cinfo->length = ntohs(m_cinfo->ip->tot_len) -
				  m_cinfo->ip->ihl * 4;

	s_cinfo->ip_data = (char *)s_cinfo->ip + s_cinfo->ip->ihl * 4;
	if (s_fragment)
		s_cinfo->length = FRAG_CB(s_cinfo->skb)->tot_len;
	else if (s_cinfo->length <= ntohs(s_cinfo->ip->tot_len))
		s_cinfo->length -= s_cinfo->ip->ihl * 4;
	else
		s_cinfo->length = ntohs(s_cinfo->ip->tot_len) -
				  s_cinfo->ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[m_cinfo->ip->protocol]);
	if (m_fragment || s_fragment) {
		if (ops && ops->compare_fragment) {
			if (!m_fragment)
				set_frag_cb(m_cinfo);
			if (!s_fragment)
				set_frag_cb(s_cinfo);
			ret = ops->compare_fragment(m_cinfo, s_cinfo);
		} else {
			if (m_cinfo->length != s_cinfo->length) {
				pr_warn("HA_compare: the length of packet is different\n");
				print_debuginfo(m_cinfo, s_cinfo);
				rcu_read_unlock();
				return CHECKPOINT | UPDATE_COMPARE_INFO;
			}
			ret = ipv4_compare_fragment(m_cinfo, s_cinfo);
		}
	} else {
		if (ops && ops->compare) {
			ret = ops->compare(m_cinfo, s_cinfo);
		} else {
//			pr_info("unknown protocol: %u", ntohs(master->protocol));
			if (m_cinfo->length != s_cinfo->length) {
				pr_warn("HA_compare: the length of packet is different\n");
				print_debuginfo(m_cinfo, s_cinfo);
				rcu_read_unlock();
				return CHECKPOINT | UPDATE_COMPARE_INFO;
			}
			ret = compare_other_packet(m_cinfo->ip_data,
						   s_cinfo->ip_data,
						   m_cinfo->length);
		}
	}
	rcu_read_unlock();
	if (ret & CHECKPOINT)
		print_debuginfo(m_cinfo, s_cinfo);

	if ((ret & SAME_PACKET) != SAME_PACKET)
		return ret;

	compare_elem(tos);
	if (!(ret & IGNORE_LEN))
		compare_elem(tot_len);
	compare_elem(frag_off);
	compare_elem(ttl);
	if (!ignore_id) {
		compare_elem(id);
		compare_elem(check);
	}

#undef compare_elem

	last_id = ntohs(m_cinfo->ip->id);

	/* ret may contain UPDATE_MASTER_PACKET */
	return ret;
}

uint32_t ipv4_compare_packet(struct compare_info *m_cinfo,
			     struct compare_info *s_cinfo)
{
	uint32_t ret = __ipv4_compare_packet(m_cinfo, s_cinfo);

	if (unlikely(ret & CHECKPOINT)) {
		same_count = 0;
		if (ret & UPDATE_COMPARE_INFO)
			ipv4_update_compare_info(m_cinfo->private_data,
						 m_cinfo->ip, m_cinfo->skb);
	} else if ((ret & SAME_PACKET) == SAME_PACKET) {
		same_count++;
	}

	if (ret & UPDATE_MASTER_PACKET) {
		BUG_ON((ret & BYPASS_MASTER) == 0);
		ipv4_update_packet(m_cinfo, s_cinfo, m_cinfo->ip->protocol);
	}

	return ret;
}

void ipv4_update_compare_info(void *info, struct iphdr *ip, struct sk_buff *skb)
{
	unsigned char protocol;
	void *data;
	uint32_t len;
	const compare_ops_t *ops;

	protocol = ip->protocol;
	data = (char *)ip + ip->ihl * 4;
	len = ntohs(ip->tot_len) - ip->ihl * 4;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->update_info)
		ops->update_info(info, data, len, skb);
	rcu_read_unlock();
}

void ipv4_flush_packets(void *info, uint8_t protocol)
{
	const compare_ops_t *ops;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[protocol]);
	if (ops && ops->flush_packets)
		ops->flush_packets(info);
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
		return CHECKPOINT | UPDATE_COMPARE_INFO;

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
			return CHECKPOINT | UPDATE_COMPARE_INFO;

		len -= cmp_len;
		if (len == 0)
			return SAME_PACKET;

		NEXT_DATA(m_skb, m_head, m_data, m_len, cmp_len);
		NEXT_DATA(s_skb, s_head, s_data, s_len, cmp_len);
	} while(len > 0);
#undef NEXT_DATA

	return CHECKPOINT | UPDATE_COMPARE_INFO;
}

uint32_t ipv4_compare_one_packet(struct compare_info *m_cinfo,
				 struct compare_info *s_cinfo)
{
	struct sk_buff *skb;
	struct compare_info *cinfo = NULL;
	struct compare_info *other_cinfo = NULL;
	uint32_t ret = 0;
	const compare_ops_t *ops;
	bool fragment;

	if (m_cinfo->skb) {
		cinfo = m_cinfo;
		other_cinfo = s_cinfo;
		ret = BYPASS_MASTER;
	} else if (s_cinfo->skb) {
		cinfo = s_cinfo;
		other_cinfo = m_cinfo;
		ret = DROP_SLAVER;
	} else
		BUG();

	skb = cinfo->skb;

	if (unlikely(cinfo->ip->ihl * 4 > cinfo->length)) {
		pr_warn("HA_compare: %s iphdr is corrupted\n",
			m_cinfo->skb ? "master" : "slaver");
		goto err;
	}

	fragment = ip_is_fragment(cinfo->ip);
	cinfo->ip_data = (char *)cinfo->ip + cinfo->ip->ihl * 4;
	if (fragment)
		cinfo->length = FRAG_CB(cinfo->skb)->tot_len;
	else if (cinfo->length <= ntohs(cinfo->ip->tot_len))
		cinfo->length -= cinfo->ip->ihl * 4;
	else
		cinfo->length = ntohs(cinfo->ip->tot_len) - cinfo->ip->ihl * 4;

	/* clear other_info to avoid unexpected errors */
	other_cinfo->ip_data = NULL;

	rcu_read_lock();
	ops = rcu_dereference(compare_inet_ops[cinfo->ip->protocol]);
	if (fragment) {
		if (ops && ops->compare_one_fragment) {
			ret = ops->compare_one_fragment(m_cinfo, s_cinfo);
		} else {
			rcu_read_unlock();
			goto unsupported;
		}
	} else {
		if (ops && ops->compare_one_packet) {
			ret = ops->compare_one_packet(m_cinfo, s_cinfo);
		} else {
			rcu_read_unlock();
			goto unsupported;
		}
	}
	rcu_read_unlock();

err:
	if (unlikely(ret & CHECKPOINT)) {
		same_count = 0;
		if (cinfo == m_cinfo && ret & UPDATE_COMPARE_INFO)
			ipv4_update_compare_info(m_cinfo->private_data,
						 m_cinfo->ip, m_cinfo->skb);
	}

	if (ret & UPDATE_MASTER_PACKET) {
		BUG_ON((ret & BYPASS_MASTER) == 0);
		BUG_ON(m_cinfo->skb == NULL);
		ipv4_update_packet(m_cinfo, s_cinfo, cinfo->ip->protocol);
	}

	return ret;

unsupported:
	return 0;
}
