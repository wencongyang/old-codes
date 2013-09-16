#ifndef IPV4_FRAGMENT_H
#define IPV4_FRAGMENT_H

extern void ipv4_frags_init(void);
extern struct sk_buff *ipv4_defrag(struct sk_buff *skb, struct ip_frags *ip_frags);
/* head: the fragment 0 of the ipv4 fragments */
extern struct sk_buff *ipv4_get_skb_by_offset(struct sk_buff *head, int offset);
/* offset: this offset shoule be in the skb */
extern void *ipv4_get_data(struct sk_buff *skb, int offset);
extern int ipv4_copy_transport_head(void *data, struct sk_buff *head, int size);

#endif
