#include <linux/kernel.h>
#include <net/tcp.h>

#include "compare.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

struct tcp_compare_info {
	uint32_t last_seq;
	uint32_t reserved[7];
};

#define TCP_CMP_INFO(compare_info) ((struct tcp_compare_info *)compare_info->private_data)

static void debug_print_tcp_header(const unsigned char *n, unsigned int doff)
{
	int i, j;

	pr_debug("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
	pr_debug("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
	pr_debug("HA_compare: %02x %02x %02x %02x\n",
		n[16], n[17], n[18], n[19]);

	/* TCP options */
	for (i = 20; i < doff; i++) {
		if (n[i] == 0)
			break;

		if (n[i] == 1) {
			/* nop */
			pr_debug("HA_compare: nop\n");
			continue;
		}

		pr_debug("HA_compare:");
		for (j = i; j < i + n[i+1]; j++) {
			pr_cont(" %02x", (unsigned int)n[j]);
		}
		pr_cont("\n");

		i += n[i+1] - 1;
	}
}

static void debug_print_tcp(void *data)
{
	unsigned int ack, seq;
	unsigned int doff;
	unsigned short src_port, dst_port;
	struct tcphdr *tcp = data;

	src_port = htons(tcp->source);
	dst_port = htons(tcp->dest);
	ack = htonl(tcp->ack_seq);
	seq = htonl(tcp->seq);
	pr_debug("HA_compare:[TCP] src=%u, dst=%u, seq = %u,"
		" ack=%u\n", src_port, dst_port, seq,
		ack);

	doff = tcp->doff * 4;
	debug_print_tcp_header(data, doff);
}

static void
update_tcp_window(struct compare_info *m, struct compare_info *s)
{
	uint16_t m_window = htons(m->tcp->window);
	uint16_t s_window = htons(s->tcp->window);

	m->tcp->window = htons(min(m_window, s_window));
	if (s_window >= m_window)
		return;

	inet_proto_csum_replace2(&m->tcp->check, m->skb, m->tcp->window,
				 s->tcp->window, 0);
}

static void
update_tcp_ackseq(struct compare_info *m, struct compare_info *s)
{
	uint32_t m_ack_seq = htonl(m->tcp->ack_seq);
	uint32_t s_ack_seq = htonl(s->tcp->ack_seq);

	m->tcp->ack_seq = htonl(min(m_ack_seq, s_ack_seq));
	if (s_ack_seq >= m_ack_seq)
		return;

	inet_proto_csum_replace4(&m->tcp->check, m->skb, m->tcp->ack_seq,
				 s->tcp->ack_seq, 0);
}

static int
compare_tcp_header(struct compare_info *m, struct compare_info *s)
{
	int m_len, s_len;
	unsigned int m_seq, s_seq;
	uint32_t ret = 0;

#define compare(elem)								\
	do {									\
		if (unlikely(m->tcp->elem != s->tcp->elem)) {			\
			pr_warn("HA_compare: tcp header's %s is different\n",	\
				#elem);						\
			return CHECKPOINT;					\
		}								\
	} while (0)

	/* source port and dest port*/
	compare(source);
	compare(dest);

	m_len = m->length - m->tcp->doff * 4;
	s_len = s->length - s->tcp->doff * 4;
	m_seq = htonl(m->tcp->seq);
	s_seq = htonl(s->tcp->seq);

	/* Sequence Number */
	if (m->tcp->syn) {
		compare(seq);
		TCP_CMP_INFO(m)->last_seq = m_seq;
	} else {

		if (ignore_retransmitted_packet) {
			if ((m_len != 0 &&
			     m_seq == TCP_CMP_INFO(m)->last_seq) ||
			    before(m_seq, TCP_CMP_INFO(m)->last_seq))
				/* retransmitted packets */
				ret |= BYPASS_MASTER;
			if ((s_len != 0 &&
			     s_seq == TCP_CMP_INFO(m)->last_seq) ||
			    before(s_seq, TCP_CMP_INFO(m)->last_seq))
				/* retransmitted packets */
				ret |= DROP_SLAVER;
		}

		if (ret)
			goto out;

		compare(seq);
	}

	/* flags */
	if(memcmp((char *)m->tcp+13, (char *)s->tcp+13, 1)) {
		pr_warn("HA_compare: tcp header's flags is different\n");
		return CHECKPOINT;
	}

	if (ignore_ack_packet) {
		if (m_len == 0 && s_len != 0)
			ret |= BYPASS_MASTER;

		if (m_len != 0 && s_len == 0)
			ret |= DROP_SLAVER;

		if (ret)
			goto out;
	}

	if (m_len != 0 || m->tcp->fin)
		TCP_CMP_INFO(m)->last_seq = m_seq;

	/* Sequence Number */
	compare(seq);

	/* data offset */
	compare(doff);

	/* tcp window size */
	if (!ignore_tcp_window)
		compare(window);

	/* Acknowledgment Number */
	if (m->tcp->ack && !ignore_ack_difference) {
		compare(ack_seq);
	}

#undef compare

	if (!ret || ret &BYPASS_MASTER) {
		if (ignore_ack_difference)
			update_tcp_ackseq(m, s);
		if (ignore_tcp_window)
			update_tcp_window(m, s);
	}

	return ret ?:SAME_PACKET;

out:
	if (ret & BYPASS_MASTER) {
		update_tcp_ackseq(m, s);
		update_tcp_window(m, s);
	}
	return ret;
}

static uint32_t compare_tcp_packet(struct compare_info *m, struct compare_info *s)
{
	int m_len, s_len;
	uint32_t ret;

	ret = compare_tcp_header(m, s);
	if (ret != SAME_PACKET)
		return ret;

	m_len = m->length - m->tcp->doff * 4;
	s_len = s->length - s->tcp->doff * 4;

	if (compare_tcp_data && m_len != 0 && s_len != 0) {
		m->tcp_data = m->ip_data + m->tcp->doff * 4;
		s->tcp_data = s->ip_data + s->tcp->doff * 4;
		ret = compare_other_packet(m->tcp_data, s->tcp_data, min(m_len, s_len));
		if (ret & CHECKPOINT) {
			pr_warn("HA_compare: tcp data is different\n");
			return CHECKPOINT;
		}
	}

	return SAME_PACKET;
}

#define IP_DATA(skb)	(void *)(ip_hdr(skb)->ihl * 4 + (char *)ip_hdr(skb))

static struct tcphdr *get_tcphdr(struct sk_buff *skb)
{
	struct tcphdr *tcph, _tcph;
	int size, ret;

	if (FRAG_CB(skb)->len < sizeof(struct tcphdr)) {
		ret = ipv4_copy_transport_head(&_tcph, skb,
					       sizeof(struct tcphdr));
		if (ret)
			return NULL;

		tcph = &_tcph;
	} else {
		tcph = IP_DATA(skb);
	}

	size = tcph->doff * 4;
	tcph = kmalloc(size, GFP_ATOMIC);
	if (!tcph)
		return NULL;

	ret = ipv4_copy_transport_head(tcph, skb, size);
	if (ret) {
		kfree(tcph);
		return NULL;
	}

	return tcph;
}

static uint32_t compare_tcpdata(struct compare_info *m, struct compare_info *s)
{
	struct sk_buff *m_head = m->skb, *s_head = s->skb;
	int m_off, s_off;

	m_off = m->tcp->doff * 4;
	s_off = s->tcp->doff * 4;

	if (m->length - m_off != s->length - s_off)
		return CHECKPOINT;

	return ipv4_transport_compare_fragment(m_head, s_head, m_off, s_off,
					       m->length - m_off);
}

static uint32_t compare_fragment(struct compare_info *m, struct compare_info *s)
{
	struct sk_buff *m_skb = m->skb;
	struct sk_buff *s_skb = s->skb;
	struct tcphdr *m_tcp = NULL, *old_m_tcp = NULL;
	struct tcphdr *s_tcp = NULL, *old_s_tcp = NULL;
	int ret = CHECKPOINT;

	if (FRAG_CB(m_skb)->len < sizeof(struct tcphdr) ||
	    FRAG_CB(m_skb)->len < m->tcp->doff * 4) {
		old_m_tcp = m->tcp;
		m->tcp = m_tcp = get_tcphdr(m_skb);
		if (!m_tcp)
			goto out;
	}

	if (FRAG_CB(s_skb)->len < sizeof(struct tcphdr) ||
	    FRAG_CB(s_skb)->len < s->tcp->doff * 4) {
		old_s_tcp = s->tcp;
		s->tcp = s_tcp = get_tcphdr(s_skb);
		if (!s_tcp)
			goto out;
	}

	ret = compare_tcp_header(m, s);
	if (ret != SAME_PACKET)
		goto out;

	if (!compare_tcp_data) {
		ret = SAME_PACKET;
		goto out;
	}

	ret = compare_tcpdata(m, s);

out:
	if (m_tcp)
		kfree(m_tcp);
	if (s_tcp)
		kfree(s_tcp);
	if (old_m_tcp)
		m->tcp = old_m_tcp;
	if (old_s_tcp)
		s->tcp = old_s_tcp;

	return ret;
}

static void update_tcp_info(void *info, void *data, uint32_t length)
{
	struct tcphdr *tcp = data;
	struct tcp_compare_info *tcp_info = info;
	uint32_t seq = htonl(tcp->seq);

	if (length <= tcp->doff * 4)
		return;

	if (after(seq, tcp_info->last_seq))
		tcp_info->last_seq = seq;
}

static compare_ops_t tcp_ops = {
	.compare = compare_tcp_packet,
	.compare_fragment = compare_fragment,
	.update_info = update_tcp_info,
	.debug_print = debug_print_tcp,
};

void compare_tcp_init(void)
{
	register_compare_ops(&tcp_ops, IPPROTO_TCP);
}

void compare_tcp_fini(void)
{
	unregister_compare_ops(&tcp_ops, IPPROTO_TCP);
}