#include <linux/module.h>
#include <linux/kernel.h>

#include "compare.h"

struct arp_reply {
	unsigned char		ar_sha[ETH_ALEN];
	unsigned char		ar_sip[4];
	unsigned char		ar_tha[ETH_ALEN];
	unsigned char		ar_tip[4];
};

uint32_t
arp_compare_packet(struct compare_info *m_cinfo, struct compare_info *s_cinfo)
{
	if (m_cinfo->length != s_cinfo->length)
		return CHECKPOINT;

	/* TODO */
	return compare_other_packet(m_cinfo->packet, s_cinfo->packet,
				    m_cinfo->length);
}

void debug_print_arp(const struct arphdr *arp)
{
	struct arp_reply *temp;

	pr_warn("HA_compare:[ARP] ar_hrd=%u, ar_pro=%u\n",
		ntohs(arp->ar_hrd), ntohs(arp->ar_pro));
	pr_warn("HA_compare:[ARP] ar_hln=%u, ar_pln=%u, ar_op=%u\n",
		arp->ar_hln, arp->ar_pln, ntohs(arp->ar_op));
	if (ntohs(arp->ar_op) == ARPOP_REPLY || ntohs(arp->ar_op) == ARPOP_REQUEST) {
		temp = (struct arp_reply *)((char*)arp + sizeof(struct arphdr));
		pr_warn("HA_compare:[ARP] ar_sha: %pM, ar_sip: %pI4\n", temp->ar_sha, temp->ar_sip);
		pr_warn("HA_compare:[ARP] ar_tha: %pM, ar_tip: %pI4\n", temp->ar_tha, temp->ar_tip);
	}
}
