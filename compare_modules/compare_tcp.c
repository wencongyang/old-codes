#include <linux/module.h>
#include <linux/kernel.h>
#include <net/tcp.h>

#include "compare.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

bool ignore_ack_packet = 1;
module_param(ignore_ack_packet, bool, 0644);
MODULE_PARM_DESC(ignore_ack_packet, "bypass ack only packet");

bool ignore_retransmitted_packet = 1;
module_param(ignore_retransmitted_packet, bool, 0644);
MODULE_PARM_DESC(ignore_retransmitted_packet, "bypass retransmitted packets");

bool compare_tcp_data = 1;
module_param(compare_tcp_data, bool, 0644);
MODULE_PARM_DESC(compare_tcp_data, "compare tcp data");

bool ignore_tcp_window = 1;
module_param(ignore_tcp_window, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_window, "ignore tcp window");

bool ignore_ack_difference = 1;
module_param(ignore_ack_difference, bool, 0644);
MODULE_PARM_DESC(ignore_ack_difference, "ignore ack difference");

bool ignore_tcp_psh = 1;
module_param(ignore_tcp_psh, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_psh, "ignore tcp psh");

bool ignore_tcp_fin = 1;
module_param(ignore_tcp_fin, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_fin, "ignore tcp fin");

bool ignore_tcp_timestamp = 1;
module_param(ignore_tcp_timestamp, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_timestamp, "ignore tcp timestamp");

struct tcp_compare_info {
	struct net_device *dev;
	uint32_t skb_iif;
	uint32_t snd_nxt;
	uint32_t rcv_nxt;
	uint16_t flags;
	uint16_t window;
	uint32_t timestamp;
	uint32_t reserved[25];
};

#define TCP_CMP_INFO(compare_info) ((struct tcp_compare_info *)compare_info->private_data)

struct tcp_hdr_info {
	uint32_t seq;
	uint32_t end_seq;
	uint32_t ack_seq;
	int length;
	unsigned int flags;
	uint32_t *timestamp;
	uint16_t window;
};

/* tcp_compare_info & tcp_hdr_info's flags */
#define		SYN		0x01
#define		FIN		0x02
#define		ACK		0x04

/* If this bit is not set, TCP_CMP_INFO() is invalid */
#define		VALID		0x08
#define		VALID_TIMESTAMP	0x10

#define		TCP_CMP_INFO_MASK	0xFFFF

/* tcp_hdr_info's flags */
#define		ERR_SKB		0x010000
#define		RETRANSMIT	0x020000
#define		WIN_UPDATE	0x040000
#define		HAVE_PAYLOAD	0x080000
#define		ACK_UPDATE	0x100000
#define		DUP_ACK		0x200000
#define		OLD_ACK		0x400000

/* FIN and PSH can be ignored */
#define		TCP_CMP_FLAGS_MASK	0xF6

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
	struct tcp_compare_info *tcp_cinfo;

	src_port = ntohs(tcp->source);
	dst_port = ntohs(tcp->dest);
	ack = ntohl(tcp->ack_seq);
	seq = ntohl(tcp->seq);
	pr_warn("HA_compare:[TCP] src=%u, dst=%u, seq = %u,"
		" ack=%u\n", src_port, dst_port, seq,
		ack);

	tcp_cinfo = TCP_CMP_INFO(info);
	if (tcp_cinfo->flags & VALID)
		pr_warn("HA_compare: snd_nxt: %u, rcv_nxt: %u\n",
			tcp_cinfo->snd_nxt, tcp_cinfo->rcv_nxt);

	doff = tcp->doff * 4;
	debug_print_tcp_header(data, doff);
}

static void
update_tcp_window(struct tcphdr *tcp, struct sk_buff *skb, uint16_t new_window)
{
	uint16_t old_window = ntohs(tcp->window);

	if (new_window >= old_window)
		return;

	tcp->window = htons(new_window);

	inet_proto_csum_replace2(&tcp->check, skb, htons(old_window),
				 tcp->window, 0);
}

static void
update_tcp_ackseq(struct tcphdr *tcp, struct sk_buff *skb, uint32_t new_ack)
{
	uint32_t old_ack = ntohl(tcp->ack_seq);

	if (!before(new_ack, old_ack))
		return;

	tcp->ack_seq = htonl(new_ack);

	inet_proto_csum_replace4(&tcp->check, skb, htonl(old_ack),
				 tcp->ack_seq, 0);
}

static void
update_tcp_psh(struct tcphdr *tcp, struct sk_buff *skb)
{
	uint16_t old_value = ((uint16_t *)tcp)[6];
	uint16_t new_value;

	tcp->psh = 1;
	new_value = ((uint16_t *)tcp)[6];
	inet_proto_csum_replace2(&tcp->check, skb, old_value, new_value, 0);
}

static void
update_tcp_fin(struct tcphdr *tcp, struct sk_buff *skb, bool clear)
{
	uint16_t old_value = ((uint16_t *)tcp)[6];
	uint16_t new_value;
	uint32_t old_seq = tcp->seq;

	tcp->fin = !clear;
	new_value=((uint16_t *)tcp)[6];

	inet_proto_csum_replace2(&tcp->check, skb, old_value, new_value, 0);
	if (clear)
		return;

	/* update the seq number */
	tcp->seq = htonl(ntohl(old_seq) - 1);
	inet_proto_csum_replace4(&tcp->check, skb, old_seq, tcp->seq, 0);
}

static void *get_next_opt_by_kind(void *opts, void *end, uint8_t kind);
/*
 * if we generate a new packet for master, the old timestamp is from
 * slaver packet. Use the timestamp from master packet instead of it.
 */
static void
update_tcp_timestamp(struct tcphdr *tcp, struct sk_buff *skb,
		     uint32_t new_timestamp)
{
	uint32_t *old_timestamp =
		get_next_opt_by_kind(tcp + 1, (char *)tcp + tcp->doff * 4,
				     TCPOPT_TIMESTAMP);

	if (!old_timestamp)
		return;

	old_timestamp = (uint32_t *)((char *)old_timestamp + 2);

	if (ntohl(*old_timestamp) == new_timestamp)
		return;

	inet_proto_csum_replace4(&tcp->check, skb, *old_timestamp,
				 htonl(new_timestamp), 0);
	*old_timestamp = htonl(new_timestamp);
}

static void
get_tcp_hdr_info(struct tcphdr *tcp, int length,
		 struct tcp_compare_info *tcp_cinfo,
		 struct tcp_hdr_info *tcp_hinfo)
{
	length -= tcp->doff * 4;

	tcp_hinfo->seq = ntohl(tcp->seq);
	tcp_hinfo->end_seq = tcp_hinfo->seq;
	tcp_hinfo->length = length;
	tcp_hinfo->window = ntohs(tcp->window);

	if (unlikely(length < 0)) {
		tcp_hinfo->flags |= ERR_SKB;
		return;
	}

	if (unlikely(tcp->fin && tcp->syn)) {
		tcp_hinfo->flags |= ERR_SKB;
		return;
	}

	tcp_hinfo->flags = 0;
	if (tcp->fin) {
		tcp_hinfo->flags |= FIN;
		tcp_hinfo->length++;
	}

	if (tcp->syn) {
		tcp_hinfo->flags |= SYN;
		tcp_hinfo->length++;
	}

	if (tcp->ack) {
		tcp_hinfo->flags |= ACK;
		tcp_hinfo->ack_seq = ntohl(tcp->ack_seq);
	}

	tcp_hinfo->end_seq += tcp_hinfo->length;

	/* timestamp */
	tcp_hinfo->timestamp =
		get_next_opt_by_kind(tcp + 1, (char *)tcp + tcp->doff * 4,
				     TCPOPT_TIMESTAMP);

	if (tcp_hinfo->timestamp)
		tcp_hinfo->timestamp =
			(uint32_t *)((char *)tcp_hinfo->timestamp + 2);

	if (length > 0)
		tcp_hinfo->flags |= HAVE_PAYLOAD;

	if (tcp->rst)
		/*
		 * rst packet, not ack update, win update, or retransmitted
		 * packet
		 */
		return;

	/*
	 * This packet is the first packet, and we can not check whether it is
	 * an ack update, win update, or retransmitted packet.
	 */
	if (!(tcp_cinfo->flags & VALID))
		return;

	/* TCP only retransmits data/SIN/FYN */
	if (tcp_hinfo->length > 0) {
		/*
		 * Retransmitted packet:
		 *  1. end_seq is before snd_nxt
		 *  2. end_seq is equal to snd_nxt, and seq is before snd_nxt
		 */
		if (before(tcp_hinfo->end_seq, tcp_cinfo->snd_nxt) ||
		    (tcp_hinfo->end_seq == tcp_cinfo->snd_nxt &&
		     before(tcp_hinfo->seq, tcp_cinfo->snd_nxt)))
			tcp_hinfo->flags |= RETRANSMIT;
	}

	/* check window update */
	if (tcp_hinfo->window > tcp_cinfo->window)
		tcp_hinfo->flags |= WIN_UPDATE;

	if ((tcp_hinfo->flags & ACK) &&
	    after(tcp_hinfo->ack_seq, tcp_cinfo->rcv_nxt))
		tcp_hinfo->flags |= ACK_UPDATE;

	if ((tcp_hinfo->flags & ACK_UPDATE) || !(tcp_hinfo->flags & ACK))
		return;

	if (tcp_hinfo->length > 0)
		return;

	/* check dup ack */
	if (tcp_hinfo->ack_seq == tcp_cinfo->rcv_nxt) {
		tcp_hinfo->flags |= DUP_ACK;
	} else {
		tcp_hinfo->flags |= OLD_ACK;

		/* old ack's window is older, ignore it */
		tcp_hinfo->flags &= ~WIN_UPDATE;
	}
}

static void
update_tcp_compare_info(struct tcp_compare_info *tcp_cinfo,
			struct tcp_hdr_info *tcp_hinfo,
			struct sk_buff *skb)
{
	if (tcp_hinfo->flags & ACK_UPDATE || !(tcp_cinfo->flags & VALID))
		tcp_cinfo->rcv_nxt = tcp_hinfo->ack_seq;

	if (!(tcp_hinfo->flags & OLD_ACK))
		tcp_cinfo->window = tcp_hinfo->window;

	if (tcp_hinfo->timestamp) {
		uint32_t timestamp = ntohl(*tcp_hinfo->timestamp);
		if (tcp_cinfo->flags & VALID_TIMESTAMP) {
			if (after(timestamp, tcp_cinfo->timestamp))
				tcp_cinfo->timestamp = timestamp;
		} else {
			tcp_cinfo->timestamp = timestamp;
			tcp_cinfo->flags |= VALID_TIMESTAMP;
		}
	}

	if (!(tcp_hinfo->flags & RETRANSMIT)) {
		uint16_t old_flags = tcp_cinfo->flags;
		tcp_cinfo->flags = (tcp_hinfo->flags & TCP_CMP_INFO_MASK) | VALID;

		/*
		 * FIN means we don't send any data more, but we can receive
		 * data. So we should not overwrite this FIN flags.
		 */
		if (old_flags & FIN && tcp_hinfo->length == 0)
			tcp_cinfo->flags |= FIN;

		if (old_flags & VALID_TIMESTAMP)
			tcp_cinfo->flags |= VALID_TIMESTAMP;
	}

	if (!(tcp_hinfo->flags & RETRANSMIT) && tcp_hinfo->length > 0)
		tcp_cinfo->snd_nxt = tcp_hinfo->end_seq;

	tcp_cinfo->dev = skb->dev;
	tcp_cinfo->skb_iif = skb->skb_iif;
}

static uint32_t check_ack_only_packet(uint32_t m_flags, uint32_t s_flags,
				      bool m_fin, bool s_fin)
{
	uint32_t ret = 0;

	if (m_fin)
		m_flags |= FIN;
	if (s_fin)
		s_flags |= FIN;

	/*
	 * 4 types of packet:
	 *   1. FIN
	 *   2. HAVE_PAYLOAD
	 *   3. FIN + HAVE_PAYLOAD
	 *   4. Ack only
	 *
	 * So there are 16 cases to be handled:
	 *     Master               Slaver              Return value
	 *     FIN+HAVE_PAYLOAD     FIN                 CHECKPOINT
	 *     FIN+HAVE_PAYLOAD     Ack only            DROP_SLAVER
	 *     FIN                  FIN+HAVE_PAYLOAD    CHECKPOINT
	 *     FIN                  HAVE_PAYLOAD        CHECKPOINT
	 *     HAVE_PAYLOAD         FIN                 CHECKPOINT
	 *     HAVE_PAYLOAD         Ack only            DROP_SLAVER
	 *     Ack only             FIN+HAVE_PAYLOAD    BYPASS_MASTER
	 *     Ack only             HAVE_PAYLOAD        BYPASS_MASTER
	 *
	 *     FIN+HAVE_PAYLOAD     FIN+HAVE_PAYLOAD    0
	 *     FIN+HAVE_PAYLOAD     HAVE_PAYLOAD        0(FIN may be cleared)
	 *     FIN                  FIN                 0
	 *     FIN                  Ack only            0(FIN may be cleared)
	 *     HAVE_PAYLOAD         FIN+HAVE_PAYLOAD    0(FIN will be remembered)
	 *     HAVE_PAYLOAD         HAVE_PAYLOAD        0
	 *     Ack only             FIN                 0(FIN will be remembered)
	 *     Ack only             Ack only            0
	 */

	/* case 9-16 */
	if ((m_flags & HAVE_PAYLOAD) == (s_flags & HAVE_PAYLOAD))
		return 0;

	/* case 1,3-5 */
	if (((m_flags & FIN) && (s_flags & HAVE_PAYLOAD)) ||
	    ((m_flags & HAVE_PAYLOAD) && (s_flags & FIN)))
		return CHECKPOINT | UPDATE_COMPARE_INFO;

	/* case 2,6-8 */
	if (m_flags & HAVE_PAYLOAD)
		ret |= DROP_SLAVER;
	if (s_flags & HAVE_PAYLOAD)
		ret |= BYPASS_MASTER;
	return ret;
}

static void *get_next_opt(void *opts, void *end)
{
	uint8_t opcode, opsize;
	uint8_t *optr = opts;
	long length = end - opts;

	while (length > 0) {
		opcode = *optr++;
		switch(opcode) {
		case TCPOPT_EOL:
			return NULL;
		case TCPOPT_NOP:
			length--;
			continue;
		default:
			if (length == 1)
				return NULL;

			opsize = *optr;
			if (opsize < 2 || opsize > length)
				return NULL;
			return optr - 1;
		}
	}

	return NULL;
}

static void *get_next_opt_by_kind(void *opts, void *end, uint8_t kind)
{
	uint8_t *optr = get_next_opt(opts, end);
	uint8_t opcode, opsize;

	while (optr != NULL) {
		opcode = *optr;
		opsize = *(optr + 1);
		if (opcode == kind)
			return optr;

		optr += opsize;
		optr = get_next_opt(optr, end);
	}

	return NULL;
}

static uint32_t compare_opt(uint8_t *m_optr, uint8_t *s_optr)
{
	uint8_t m_opcode, m_opsize;
	uint8_t s_opcode, s_opsize;

	m_opcode = *m_optr++;
	m_opsize = *m_optr++;
	s_opcode = *s_optr++;
	s_opsize = *s_optr++;

	BUG_ON(m_opcode != s_opcode);
	if (m_opsize != s_opsize)
		/* TODO: SACK */
		return CHECKPOINT | UPDATE_COMPARE_INFO;

	if (m_opsize == 2)
		return 0;

	if (m_opcode != TCPOPT_TIMESTAMP)
		return memcmp(m_optr, s_optr, m_opsize - 2) ? CHECKPOINT | UPDATE_COMPARE_INFO : 0;

	if (!ignore_tcp_timestamp)
		return memcmp(m_optr, s_optr, m_opsize - 2) ? CHECKPOINT | UPDATE_COMPARE_INFO : 0;

	/* TODO:  TIMESTAMP */
	return 0;
}

static uint32_t
compare_tcp_options(void *m_opts, void *m_opts_end, void *s_opts, void *s_opts_end)
{
	void *m_opt = get_next_opt(m_opts, m_opts_end);
	void *s_opt = get_next_opt(s_opts, s_opts_end);
	uint8_t opcode, opsize;
	uint8_t *m_optr = m_opt;
	uint8_t *s_optr = s_opt;
	uint32_t ret;

	if (!m_opt && !s_opt)
		return 0;

	if (!m_opt || !s_opt)
		return CHECKPOINT | UPDATE_COMPARE_INFO;

	while (m_optr != NULL) {
		opcode = *m_optr;
		opsize = *(m_optr + 1);

		s_optr = get_next_opt_by_kind(s_opt, s_opts_end, opcode);
		if (!s_optr)
			/* TODO: SACK */
			return CHECKPOINT | UPDATE_COMPARE_INFO;

		ret = compare_opt(m_optr, s_optr);
		if (ret)
			return ret;

		m_optr += opsize;
		m_optr = get_next_opt(m_optr, m_opts_end);
	}

	s_optr = s_opt;
	while (s_optr != NULL) {
		opcode = *s_optr;
		opsize = *(s_optr + 1);

		m_optr = get_next_opt_by_kind(m_opt, m_opts_end, opcode);
		if (!m_optr)
			/* TODO: SACK */
			return CHECKPOINT | UPDATE_COMPARE_INFO;

		s_optr += opsize;
		s_optr = get_next_opt(s_optr, s_opts_end);
	}

	return 0;
}

static int
tcp_compare_header(struct compare_info *m_cinfo, struct compare_info *s_cinfo,
		   struct tcp_hdr_info *m_tcp_hinfo,
		   struct tcp_hdr_info *s_tcp_hinfo)
{
	uint8_t m_flags, s_flags;
	uint32_t ret = 0;

#define compare(elem)								\
	do {									\
		if (unlikely(m_cinfo->tcp->elem != s_cinfo->tcp->elem)) {	\
			pr_warn("HA_compare: tcp header's %s is different\n",	\
				#elem);						\
			return CHECKPOINT | UPDATE_COMPARE_INFO;		\
		}								\
	} while (0)

	/* source port and dest port*/
	compare(source);
	compare(dest);

	if (m_tcp_hinfo->flags & ERR_SKB)
		ret |= BYPASS_MASTER;
	if (m_tcp_hinfo->flags & ERR_SKB)
		ret |= DROP_SLAVER;
	if (ret)
		return ret;

	if (ignore_retransmitted_packet) {
		if (m_tcp_hinfo->flags & RETRANSMIT)
			ret |= BYPASS_MASTER;
		if (s_tcp_hinfo->flags & RETRANSMIT)
			ret |= DROP_SLAVER;
		if (ret)
			goto out;
	}

	/* seq */
	if ((TCP_CMP_INFO(m_cinfo)->flags & FIN) !=
	    (TCP_CMP_INFO(s_cinfo)->flags & FIN)) {
		uint32_t m_seq = ntohl(m_cinfo->tcp->seq);
		uint32_t s_seq = ntohl(s_cinfo->tcp->seq);

		if (TCP_CMP_INFO(m_cinfo)->flags & FIN)
			m_seq -= 1;
		if (TCP_CMP_INFO(s_cinfo)->flags & FIN)
			s_seq -= 1;
		if (unlikely(m_seq != s_seq)) {
			pr_warn("HA_compare: tcp header's seq is different\n");
			return CHECKPOINT | UPDATE_COMPARE_INFO;
		}
	} else
		compare(seq);

	/* flags */
	m_flags = *(uint8_t *)((char *)m_cinfo->tcp + 13);
	s_flags = *(uint8_t *)((char *)s_cinfo->tcp + 13);
	if ((m_flags & TCP_CMP_FLAGS_MASK) != (s_flags & TCP_CMP_FLAGS_MASK)) {
		pr_warn("HA_compare: tcp header's flags is different\n");
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	if (!ignore_tcp_psh) {
		if (m_cinfo->tcp->psh != s_cinfo->tcp->psh) {
			pr_warn("HA_compare: tcp header's flags is different\n");
			return CHECKPOINT | UPDATE_COMPARE_INFO;
		}
	}

	if (!ignore_tcp_fin) {
		if (m_cinfo->tcp->fin != s_cinfo->tcp->fin) {
			pr_warn("HA_compare: tcp header's flags is different\n");
			return CHECKPOINT | UPDATE_COMPARE_INFO;
		}
	}

	if (ignore_ack_packet) {
		ret = check_ack_only_packet(m_tcp_hinfo->flags,
					    s_tcp_hinfo->flags,
					    TCP_CMP_INFO(m_cinfo)->flags & FIN,
					    TCP_CMP_INFO(s_cinfo)->flags & FIN);
		if (ret)
			goto out;
	}

	/* data offset */
	compare(doff);

	ret = compare_tcp_options(m_cinfo->ip_data + sizeof(struct tcphdr),
				  m_cinfo->ip_data + m_cinfo->tcp->doff * 4,
				  s_cinfo->ip_data + sizeof(struct tcphdr),
				  s_cinfo->ip_data + s_cinfo->tcp->doff * 4);
	if (ret) {
		pr_warn("HA_compare: tcp header's options are different\n");
		return CHECKPOINT | UPDATE_COMPARE_INFO;
	}

	/* tcp window size */
	if (!ignore_tcp_window)
		compare(window);

	/* Acknowledgment Number */
	if (m_cinfo->tcp->ack && !ignore_ack_difference) {
		compare(ack_seq);
	}

#undef compare
	/* update flags */
	/* PSH */
	if (m_cinfo->tcp->psh != s_cinfo->tcp->psh && !m_cinfo->tcp->psh)
		update_tcp_psh(m_cinfo->tcp, m_cinfo->skb);

	/* FIN */
	if (TCP_CMP_INFO(m_cinfo)->flags & FIN && !m_cinfo->tcp->fin &&
	    s_cinfo->tcp->fin) {
		/* add the flags FIN again */
		update_tcp_fin(m_cinfo->tcp, m_cinfo->skb, false);
	} else if (m_cinfo->tcp->fin &&
		   !(TCP_CMP_INFO(s_cinfo)->flags & FIN) &&
		   !s_cinfo->tcp->fin) {
		/* clear the flags FIN */
		update_tcp_fin(m_cinfo->tcp, m_cinfo->skb, true);
	}

	update_tcp_compare_info(TCP_CMP_INFO(m_cinfo), m_tcp_hinfo,
				m_cinfo->skb);
	update_tcp_compare_info(TCP_CMP_INFO(s_cinfo), s_tcp_hinfo,
				s_cinfo->skb);

	if (ignore_ack_difference)
		update_tcp_ackseq(m_cinfo->tcp, m_cinfo->skb,
				  s_tcp_hinfo->ack_seq);
	if (ignore_tcp_window)
		update_tcp_window(m_cinfo->tcp, m_cinfo->skb,
				  s_tcp_hinfo->window);

	return SAME_PACKET;

out:
	/* Retransmitted packet or ack only packet */
	if (ret & BYPASS_MASTER) {
		/* clear FIN flags first before bypass master packet */
		if (m_tcp_hinfo->flags & RETRANSMIT && m_cinfo->tcp->fin &&
		    !(TCP_CMP_INFO(s_cinfo)->flags & FIN))
			update_tcp_fin(m_cinfo->tcp, m_cinfo->skb, true);
		update_tcp_compare_info(TCP_CMP_INFO(m_cinfo), m_tcp_hinfo,
					m_cinfo->skb);
		update_tcp_ackseq(m_cinfo->tcp, m_cinfo->skb,
				  s_tcp_hinfo->ack_seq);
		update_tcp_window(m_cinfo->tcp, m_cinfo->skb,
				  s_tcp_hinfo->window);
	}
	if (ret & DROP_SLAVER) {
		update_tcp_compare_info(TCP_CMP_INFO(s_cinfo), s_tcp_hinfo,
					s_cinfo->skb);
	}
	return ret;
}

static uint32_t tcp_compare_packet(struct compare_info *m_cinfo,
				   struct compare_info *s_cinfo)
{
	int m_len, s_len;
	uint32_t ret;
	struct tcp_hdr_info m_tcp_hinfo, s_tcp_hinfo;

	get_tcp_hdr_info(m_cinfo->tcp, m_cinfo->length, TCP_CMP_INFO(m_cinfo),
			 &m_tcp_hinfo);
	get_tcp_hdr_info(s_cinfo->tcp, s_cinfo->length, TCP_CMP_INFO(s_cinfo),
			 &s_tcp_hinfo);

	ret = tcp_compare_header(m_cinfo, s_cinfo, &m_tcp_hinfo, &s_tcp_hinfo);
	if (ret != SAME_PACKET)
		return ret;

	m_len = m_cinfo->length - m_cinfo->tcp->doff * 4;
	s_len = s_cinfo->length - s_cinfo->tcp->doff * 4;

	if (compare_tcp_data && m_len != 0 && s_len != 0) {
		m_cinfo->tcp_data = m_cinfo->ip_data + m_cinfo->tcp->doff * 4;
		s_cinfo->tcp_data = s_cinfo->ip_data + s_cinfo->tcp->doff * 4;
		ret = compare_other_packet(m_cinfo->tcp_data,
					   s_cinfo->tcp_data,
					   min(m_len, s_len));
		if (ret & CHECKPOINT) {
			pr_warn("HA_compare: tcp data is different\n");
			return CHECKPOINT | UPDATE_COMPARE_INFO;
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

static uint32_t
tcp_compare_payload(struct compare_info *m_cinfo,
		    struct compare_info *s_cinfo)
{
	struct sk_buff *m_head = m_cinfo->skb, *s_head = s_cinfo->skb;
	int m_off, s_off;

	m_off = m_cinfo->tcp->doff * 4;
	s_off = s_cinfo->tcp->doff * 4;

	if (m_cinfo->length - m_off != s_cinfo->length - s_off)
		return CHECKPOINT | UPDATE_COMPARE_INFO;

	return ipv4_transport_compare_fragment(m_head, s_head, m_off, s_off,
					       m_cinfo->length - m_off);
}

static uint32_t
tcp_compare_fragment(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	struct sk_buff *m_skb = m_cinfo->skb;
	struct sk_buff *s_skb = s_cinfo->skb;
	struct tcphdr *m_tcp = NULL, *old_m_tcp = NULL;
	struct tcphdr *s_tcp = NULL, *old_s_tcp = NULL;
	int ret = CHECKPOINT | UPDATE_COMPARE_INFO;
	struct tcp_hdr_info m_tcp_hinfo, s_tcp_hinfo;

	if (FRAG_CB(m_skb)->len < sizeof(struct tcphdr) ||
	    FRAG_CB(m_skb)->len < m_cinfo->tcp->doff * 4) {
		old_m_tcp = m_cinfo->tcp;
		m_cinfo->tcp = m_tcp = get_tcphdr(m_skb);
		if (!m_tcp)
			goto out;
	}

	if (FRAG_CB(s_skb)->len < sizeof(struct tcphdr) ||
	    FRAG_CB(s_skb)->len < s_cinfo->tcp->doff * 4) {
		old_s_tcp = s_cinfo->tcp;
		s_cinfo->tcp = s_tcp = get_tcphdr(s_skb);
		if (!s_tcp)
			goto out;
	}

	get_tcp_hdr_info(m_cinfo->tcp, m_cinfo->length, TCP_CMP_INFO(m_cinfo),
			 &m_tcp_hinfo);
	get_tcp_hdr_info(s_cinfo->tcp, s_cinfo->length, TCP_CMP_INFO(s_cinfo),
			 &s_tcp_hinfo);

	ret = tcp_compare_header(m_cinfo, s_cinfo, &m_tcp_hinfo, &s_tcp_hinfo);
	if (ret != SAME_PACKET)
		goto out;

	if (!compare_tcp_data) {
		ret = SAME_PACKET;
		goto out;
	}

	ret = tcp_compare_payload(m_cinfo, s_cinfo);

out:
	if (m_tcp)
		kfree(m_tcp);
	if (s_tcp)
		kfree(s_tcp);
	if (old_m_tcp)
		m_cinfo->tcp = old_m_tcp;
	if (old_s_tcp)
		s_cinfo->tcp = old_s_tcp;

	return ret;
}

static struct sk_buff *create_new_skb(struct sk_buff *skb,
				      struct compare_info *cinfo)
{
	struct sk_buff *new_skb;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;

	new_skb = skb_copy(skb, GFP_ATOMIC);
	if (!new_skb)
		return NULL;

	new_skb->dev = TCP_CMP_INFO(cinfo)->dev;
	new_skb->skb_iif = TCP_CMP_INFO(cinfo)->skb_iif;
	cinfo->skb = new_skb;

	eth = (struct ethhdr *)new_skb->data;
	if (unlikely(ntohs(eth->h_proto) != ETH_P_IP))
		goto err;

	ip = (struct iphdr *)((char *)eth + sizeof(struct ethhdr));
	if (unlikely(ip->protocol != IPPROTO_TCP))
		goto err;

	tcp = (struct tcphdr *)((char *)ip + ip->ihl * 4);

	cinfo->eth = eth;
	cinfo->ip = ip;
	cinfo->tcp = tcp;

	return new_skb;

err:
	pr_warn("OOPS, origin skb is not TCP packet.\n");
	kfree_skb(new_skb);
	return NULL;
}

static void
update_tcp_hdr_flags(struct compare_info *cinfo,
		     struct compare_info *other_cinfo,
		     struct tcp_hdr_info *tcp_hinfo)
{
	struct tcp_compare_info *tcp_cinfo = TCP_CMP_INFO(cinfo);
	struct tcp_compare_info *other_tcp_cinfo = TCP_CMP_INFO(other_cinfo);

	/* more check for window update */
	if (tcp_hinfo->flags & WIN_UPDATE)
		if (tcp_cinfo->window >= other_tcp_cinfo->window)
			tcp_hinfo->flags &= ~WIN_UPDATE;

	/* more check for ack_seq update */
	if (tcp_hinfo->flags & ACK_UPDATE)
		if (!after(other_tcp_cinfo->rcv_nxt, tcp_cinfo->rcv_nxt))
			tcp_hinfo->flags &= ~ACK_UPDATE;
}

static uint32_t
tcp_compare_one_packet(struct compare_info *m_cinfo,
		       struct compare_info *s_cinfo)
{
	struct sk_buff *skb, *new_skb = NULL;
	struct compare_info *cinfo, *other_cinfo;
	struct tcp_hdr_info tcp_hinfo;
	struct tcphdr *tcp;
	int ret = 0;

	/* compare one packet is only for tcp ack, window and fin */
	if (!ignore_ack_packet && !ignore_ack_difference &&
	    !ignore_tcp_window && !ignore_tcp_fin)
		return 0;

	if (m_cinfo->skb) {
		cinfo = m_cinfo;
		other_cinfo = s_cinfo;
		ret |= BYPASS_MASTER;
	} else if (s_cinfo->skb) {
		cinfo = s_cinfo;
		other_cinfo = m_cinfo;
		ret |= DROP_SLAVER;
	} else
		BUG();

	skb = cinfo->skb;
	get_tcp_hdr_info(cinfo->tcp, cinfo->length, TCP_CMP_INFO(cinfo),
			 &tcp_hinfo);

	if (unlikely(tcp_hinfo.flags & ERR_SKB))
		return ret;

	if (!ignore_ack_difference && tcp_hinfo.flags & ACK_UPDATE)
		return 0;

	if (!ignore_tcp_window && tcp_hinfo.flags & WIN_UPDATE)
		return 0;

	/* more check for window and ack_seq update */
	update_tcp_hdr_flags(cinfo, other_cinfo, &tcp_hinfo);

	if (tcp_hinfo.flags & RETRANSMIT) {
		/* clear FIN */
		if (cinfo->tcp->fin && !(TCP_CMP_INFO(other_cinfo)->flags & FIN))
			update_tcp_fin(cinfo->tcp, cinfo->skb, true);

		/* Retransmitted packet may conatin WIN_UPDATE or ACK_UPDATE */
		if (tcp_hinfo.flags & ACK_UPDATE ||
		    tcp_hinfo.flags & WIN_UPDATE)
			/* TODO: How to avoid retransmiting twice? */
			goto send_packet;

		update_tcp_compare_info(TCP_CMP_INFO(cinfo), &tcp_hinfo,
					cinfo->skb);

		tcp = cinfo->tcp;
		update_tcp_ackseq(tcp, skb, TCP_CMP_INFO(other_cinfo)->rcv_nxt);
		update_tcp_window(tcp, skb, TCP_CMP_INFO(other_cinfo)->window);
		return ret;
	}

	if ((tcp_hinfo.flags & HAVE_PAYLOAD) &&
	    (TCP_CMP_INFO(other_cinfo)->flags & FIN))
		return CHECKPOINT | UPDATE_COMPARE_INFO;

	if (tcp_hinfo.flags & (HAVE_PAYLOAD | SYN))
		/*
		 * This packet is not a retransmitted packet,
		 * and has data or SYN.
		 */
		return 0;

	if ((tcp_hinfo.flags & FIN) &&
	    (TCP_CMP_INFO(other_cinfo)->flags & FIN))
		goto send_packet;

	if (tcp_hinfo.flags & OLD_ACK)
		/* It is a packet with old ack seq */
		return ret;

	if (!(tcp_hinfo.flags & (WIN_UPDATE | ACK_UPDATE | DUP_ACK)))
		return 0;

send_packet:
	if (s_cinfo->skb) {
		new_skb = create_new_skb(skb, m_cinfo);
		if (!new_skb)
			return 0;
	} else
		new_skb = skb;
	update_tcp_compare_info(TCP_CMP_INFO(cinfo), &tcp_hinfo,
				cinfo->skb);

	if (cinfo == s_cinfo) {
		tcp = m_cinfo->tcp;
		update_tcp_ackseq(tcp, new_skb,
				  TCP_CMP_INFO(other_cinfo)->rcv_nxt);
		update_tcp_window(tcp, new_skb,
				  TCP_CMP_INFO(other_cinfo)->window);
		update_tcp_timestamp(tcp, new_skb,
				     TCP_CMP_INFO(other_cinfo)->timestamp);
	}

	return cinfo == m_cinfo ? BYPASS_MASTER : SAME_PACKET;
}

static void tcp_update_info(void *info, void *data, uint32_t length, struct sk_buff *skb)
{
	struct tcphdr *tcp = data;
	struct tcp_compare_info *tcp_cinfo = info;
	struct tcp_hdr_info tcp_hinfo;

	get_tcp_hdr_info(tcp, length, tcp_cinfo, &tcp_hinfo);

	if (unlikely(tcp_hinfo.flags & ERR_SKB))
		return;

	update_tcp_compare_info(tcp_cinfo, &tcp_hinfo, skb);
}

static compare_ops_t tcp_ops = {
	.compare = tcp_compare_packet,
	.compare_one_packet = tcp_compare_one_packet,
	.compare_fragment = tcp_compare_fragment,
	.update_info = tcp_update_info,
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
