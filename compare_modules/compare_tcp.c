#include <linux/kernel.h>
#include <net/tcp.h>

#include "compare.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

struct tcp_compare_info {
	struct net_device *dev;
	uint32_t snd_nxt;
	uint32_t rcv_nxt;
	uint16_t flags;
	uint16_t window;
	uint32_t reserved[3];
};

#define TCP_CMP_INFO(compare_info) ((struct tcp_compare_info *)compare_info->private_data)

struct tcphdr_info {
	uint32_t seq;
	uint32_t end_seq;
	uint32_t ack_seq;
	int length;
	unsigned int flags;
	uint16_t window;
};

/* tcp_compare_info & tcphdr_info's flags */
#define		SYN		0x01
#define		FIN		0x02
#define		ACK		0x04

/* If this bit is not set, TCP_CMP_INFO() is invalid */
#define		VALID		0x08

#define		TCP_CMP_INFO_MASK	0xFFFF

/* tcphdr_info's flags */
#define		ERR_SKB		0x010000
#define		RETRANSMIT	0x020000
#define		WIN_UPDATE	0x040000
#define		HAVE_PAYLOAD	0x080000
#define		ACK_UPDATE	0x100000
#define		DUP_ACK		0x200000
#define		OLD_ACK		0x400000

static void debug_print_tcp_header(const unsigned char *n, unsigned int doff)
{
	int i, j;

	pr_warn("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
	pr_warn("HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
	pr_warn("HA_compare: %02x %02x %02x %02x\n",
		n[16], n[17], n[18], n[19]);

	/* TCP options */
	for (i = 20; i < doff; i++) {
		if (n[i] == 0)
			break;

		if (n[i] == 1) {
			/* nop */
			pr_warn("HA_compare: nop\n");
			continue;
		}

		pr_warn("HA_compare:");
		for (j = i; j < i + n[i+1]; j++) {
			pr_cont(" %02x", (unsigned int)n[j]);
		}
		pr_cont("\n");

		i += n[i+1] - 1;
	}
}

static void debug_print_tcp(const struct compare_info *info, const void *data)
{
	unsigned int ack, seq;
	unsigned int doff;
	unsigned short src_port, dst_port;
	const struct tcphdr *tcp = data;
	struct tcp_compare_info *tcp_info;

	src_port = htons(tcp->source);
	dst_port = htons(tcp->dest);
	ack = htonl(tcp->ack_seq);
	seq = htonl(tcp->seq);
	pr_warn("HA_compare:[TCP] src=%u, dst=%u, seq = %u,"
		" ack=%u\n", src_port, dst_port, seq,
		ack);

	tcp_info = TCP_CMP_INFO(info);
	if (tcp_info->flags & VALID)
		pr_warn("HA_compare: snd_nxt: %u, rcv_nxt: %u\n",
			tcp_info->snd_nxt, tcp_info->rcv_nxt);

	doff = tcp->doff * 4;
	debug_print_tcp_header(data, doff);
}

static void
update_tcp_window(struct tcphdr *tcp, struct sk_buff *skb, uint16_t new_window)
{
	uint16_t old_window = htons(tcp->window);

	if (new_window >= old_window)
		return;

	tcp->window = htons(new_window);

	inet_proto_csum_replace2(&tcp->check, skb, tcp->window,
				 htons(new_window), 0);
}

static void
update_tcp_ackseq(struct tcphdr *tcp, struct sk_buff *skb, uint32_t new_ack)
{
	uint32_t old_ack = htonl(tcp->ack_seq);

	if (!before(new_ack, old_ack))
		return;

	tcp->ack_seq = htonl(new_ack);

	inet_proto_csum_replace4(&tcp->check, skb, tcp->ack_seq,
				 htonl(old_ack), 0);
}

static void
get_tcphdr_info(struct tcphdr *tcp, int length,
		struct tcp_compare_info *tcp_info,
		struct tcphdr_info *tcphdr_info)
{
	length -= tcp->doff * 4;

	tcphdr_info->seq = htonl(tcp->seq);
	tcphdr_info->end_seq = tcphdr_info->seq;
	tcphdr_info->length = length;
	tcphdr_info->window = htons(tcp->window);

	if (unlikely(length < 0)) {
		tcphdr_info->flags |= ERR_SKB;
		return;
	}

	if (unlikely(tcp->fin && tcp->syn)) {
		tcphdr_info->flags |= ERR_SKB;
		return;
	}

	tcphdr_info->flags = 0;
	if (tcp->fin) {
		tcphdr_info->flags |= FIN;
		tcphdr_info->length++;
	}

	if (tcp->syn) {
		tcphdr_info->flags |= SYN;
		tcphdr_info->length++;
	}

	if (tcp->ack) {
		tcphdr_info->flags |= ACK;
		tcphdr_info->ack_seq = htonl(tcp->ack_seq);
	}

	tcphdr_info->end_seq += tcphdr_info->length;
	if (!(tcp_info->flags & VALID))
		return;

	if (length > 0)
		tcphdr_info->flags |= HAVE_PAYLOAD;

	if (tcphdr_info->length > 0)
		goto check_retransmitted_packet;

	/* check window update */
	if (tcphdr_info->window > tcp_info->window)
		tcphdr_info->flags |= WIN_UPDATE;

	if ((tcphdr_info->flags & ACK) &&
	    after(tcphdr_info->ack_seq, tcp_info->rcv_nxt))
		tcphdr_info->flags |= ACK_UPDATE;

check_retransmitted_packet:
	/*
	 * Retransmitted packet:
	 *  1. end_seq is before snd_nxt
	 *  2. end_seq is equal to snd_nxt, and seq is before snd_nxt
	 */
	if (before(tcphdr_info->end_seq, tcp_info->snd_nxt) ||
	    (tcphdr_info->end_seq == tcp_info->snd_nxt &&
	     before(tcphdr_info->seq, tcp_info->snd_nxt)))
		tcphdr_info->flags |= RETRANSMIT;

	if ((tcphdr_info->flags & ACK_UPDATE) || !(tcphdr_info->flags & ACK))
		return;

	/* check dup ack */
	if (tcphdr_info->ack_seq == tcp_info->rcv_nxt) {
		tcphdr_info->flags |= DUP_ACK;
	} else {
		tcphdr_info->flags |= OLD_ACK;

		/* old ack's window is older, ignore it */
		tcphdr_info->flags &= ~WIN_UPDATE;
	}
}

static void
update_tcp_compare_info(struct tcp_compare_info *tcp_info,
			struct tcphdr_info *tcphdr_info)
{
	if (tcphdr_info->flags & ACK_UPDATE)
		tcp_info->rcv_nxt = tcphdr_info->ack_seq;

	if (!(tcphdr_info->flags & OLD_ACK))
		tcp_info->window = tcphdr_info->window;

	if (!(tcphdr_info->flags & RETRANSMIT))
		tcp_info->flags = (tcphdr_info->flags & TCP_CMP_INFO_MASK) | VALID;

	if (!(tcphdr_info->flags & RETRANSMIT) && tcphdr_info->length > 0)
		tcp_info->snd_nxt = tcphdr_info->end_seq;
}

static int
compare_tcp_header(struct compare_info *m, struct compare_info *s)
{
	struct tcphdr_info m_info, s_info;
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

	get_tcphdr_info(m->tcp, m->length, TCP_CMP_INFO(m), &m_info);
	get_tcphdr_info(s->tcp, s->length, TCP_CMP_INFO(s), &s_info);
	if (m_info.flags & ERR_SKB)
		ret |= BYPASS_MASTER;
	if (m_info.flags & ERR_SKB)
		ret |= DROP_SLAVER;
	if (ret)
		return ret;

	if (ignore_retransmitted_packet) {
		if (m_info.flags & RETRANSMIT)
			ret |= BYPASS_MASTER;
		if (s_info.flags & RETRANSMIT)
			ret |= DROP_SLAVER;
		if (ret)
			goto out;
	}

	compare(seq);

	/* flags */
	if(memcmp((char *)m->tcp+13, (char *)s->tcp+13, 1)) {
		pr_warn("HA_compare: tcp header's flags is different\n");
		return CHECKPOINT;
	}

	if (ignore_ack_packet) {
		if ((m_info.flags & HAVE_PAYLOAD) !=
		    (s_info.flags & HAVE_PAYLOAD)) {
			if (m_info.flags & HAVE_PAYLOAD)
				ret |= DROP_SLAVER;
			if (s_info.flags & HAVE_PAYLOAD)
				ret |= BYPASS_MASTER;
			goto out;
		}
	}

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

	update_tcp_compare_info(TCP_CMP_INFO(m), &m_info);
	TCP_CMP_INFO(m)->dev = m->skb->dev;
	update_tcp_compare_info(TCP_CMP_INFO(s), &s_info);
	TCP_CMP_INFO(s)->dev = s->skb->dev;

	if (ignore_ack_difference)
		update_tcp_ackseq(m->tcp, m->skb, s_info.ack_seq);
	if (ignore_tcp_window)
		update_tcp_window(m->tcp, m->skb, s_info.window);

	return SAME_PACKET;

out:
	if (ret & BYPASS_MASTER) {
		update_tcp_compare_info(TCP_CMP_INFO(m), &m_info);
		TCP_CMP_INFO(m)->dev = m->skb->dev;
		update_tcp_ackseq(m->tcp, m->skb, s_info.ack_seq);
		update_tcp_window(m->tcp, m->skb, s_info.window);
	}
	if (ret & DROP_SLAVER) {
		update_tcp_compare_info(TCP_CMP_INFO(s), &s_info);
		TCP_CMP_INFO(s)->dev = s->skb->dev;
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

static struct sk_buff *create_new_skb(struct sk_buff *skb,
				      struct compare_info *info)
{
	struct sk_buff *new_skb;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;

	new_skb = skb_copy(skb, GFP_ATOMIC);
	if (!new_skb)
		return NULL;

	new_skb->dev = TCP_CMP_INFO(info)->dev;
	new_skb->skb_iif = new_skb->dev->ifindex;
	info->skb = new_skb;

	eth = (struct ethhdr *)new_skb->data;
	if (unlikely(ntohs(eth->h_proto) != ETH_P_IP))
		goto err;

	ip = (struct iphdr *)((char *)eth + sizeof(struct ethhdr));
	if (unlikely(ip->protocol != IPPROTO_TCP))
		goto err;

	tcp = (struct tcphdr *)((char *)ip + ip->ihl * 4);

	info->eth = eth;
	info->ip = ip;
	info->tcp = tcp;

	return new_skb;

err:
	pr_warn("OOPS, origin skb is not TCP packet.\n");
	kfree_skb(new_skb);
	return NULL;
}

static void
update_tcphdr_flags(struct compare_info *info,
		    struct compare_info *other_info,
		    struct tcphdr_info *tcphdr_info)
{
	struct tcp_compare_info *tcp_info = TCP_CMP_INFO(info);
	struct tcp_compare_info *other_tcp_info = TCP_CMP_INFO(other_info);

	/* more check for window update */
	if (tcphdr_info->flags & WIN_UPDATE)
		if (tcp_info->window <= other_tcp_info->window)
			tcphdr_info->flags &= ~WIN_UPDATE;

	/* more check for ack_seq update */
	if (tcphdr_info->flags & ACK_UPDATE)
		if (!after(other_tcp_info->rcv_nxt, tcp_info->rcv_nxt))
			tcphdr_info->flags &= ~ACK_UPDATE;
}

static uint32_t
tcp_compare_one_packet(struct compare_info *m, struct compare_info *s)
{
	struct sk_buff *skb, *new_skb = NULL;
	struct compare_info *info, *other_info;
	struct tcphdr_info tcphdr_info;
	struct tcphdr *tcp;
	int ret = 0;

	if (m->skb) {
		info = m;
		other_info = s;
		ret |= BYPASS_MASTER;
	} else if (s->skb) {
		info = s;
		other_info = m;
		ret |= DROP_SLAVER;
	} else
		BUG();

	skb = info->skb;
	get_tcphdr_info(info->tcp, info->length, TCP_CMP_INFO(info),
			&tcphdr_info);

	if (unlikely(tcphdr_info.flags & ERR_SKB))
		return ret;

	/* more check for window and ack_seq update */
	update_tcphdr_flags(info, other_info, &tcphdr_info);

	if (tcphdr_info.flags & RETRANSMIT) {
		/* Retransmitted packet may conatin WIN_UPDATE or ACK_UPDATE */
		if (tcphdr_info.flags & ACK_UPDATE ||
		    tcphdr_info.flags & WIN_UPDATE)
			/* TODO: How to avoid retransmiting twice? */
			goto send_packet;

		update_tcp_compare_info(TCP_CMP_INFO(info), &tcphdr_info);
		TCP_CMP_INFO(info)->dev = info->skb->dev;

		tcp = info->tcp;
		update_tcp_ackseq(tcp, skb, TCP_CMP_INFO(other_info)->rcv_nxt);
		update_tcp_window(tcp, skb, TCP_CMP_INFO(other_info)->window);
		return ret;
	}

	if (tcphdr_info.length > 0)
		/*
		 * This packet is not a retransmitted packet,
		 * and has data or FIN or SYN.
		 */
		return 0;

	if (tcphdr_info.flags & OLD_ACK)
		/* It is a packet with old ack seq */
		return ret;

	if (!(tcphdr_info.flags & (WIN_UPDATE | ACK_UPDATE | DUP_ACK)))
		return 0;

send_packet:
	if (s->skb) {
		new_skb = create_new_skb(skb, m);
		if (!new_skb)
			return 0;
	} else
		new_skb = skb;
	update_tcp_compare_info(TCP_CMP_INFO(info), &tcphdr_info);
	TCP_CMP_INFO(info)->dev = info->skb->dev;

	tcp = m->tcp;
	update_tcp_ackseq(tcp, new_skb, TCP_CMP_INFO(other_info)->rcv_nxt);
	update_tcp_window(tcp, new_skb, TCP_CMP_INFO(other_info)->window);

	return info == m ? BYPASS_MASTER : SAME_PACKET;
}

static void update_tcp_info(void *info, void *data, uint32_t length, struct sk_buff *skb)
{
	struct tcphdr *tcp = data;
	struct tcp_compare_info *tcp_info = info;
	struct tcphdr_info tcphdr_info;

	get_tcphdr_info(tcp, length, tcp_info, &tcphdr_info);

	if (unlikely(tcphdr_info.flags & ERR_SKB))
		return;

	update_tcp_compare_info(tcp_info, &tcphdr_info);
	tcp_info->dev = skb->dev;
}

static compare_ops_t tcp_ops = {
	.compare = compare_tcp_packet,
	.compare_one_packet = tcp_compare_one_packet,
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
