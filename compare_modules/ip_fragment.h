#ifndef IP_FRAGMENT_H
#define IP_FRAGMENT_H

struct ip_frag_bucket {
	struct hlist_head chain;
	spinlock_t chain_lock;
};

struct ip_frags {
	int nqueues;
	struct list_head lru_list;
	spinlock_t lru_lock;
};

struct frag_queue {
	spinlock_t		lock;
	struct timer_list	timer;      /* when will this queue expire? */
	struct list_head	lru_list;   /* lru list member */
	struct hlist_node	list;
	atomic_t		refcnt;
	struct sk_buff		*fragments; /* list of received fragments */
	struct sk_buff		*fragments_tail;
	int			len;        /* total length of orig datagram */
	int			meat;
	__u8			last_in;    /* first/last segment arrived? */

	struct ip_frags		*ip_frags;
	struct ip_frag_bucket	*hb;
};

struct ipfrag_skb_cb
{
	int			is_fragment;
	int			offset;
	int			len;

	/* Only for fragment0 */
	int			tot_len;
};

#define FRAG_CB(skb)	((struct ipfrag_skb_cb *)((skb)->cb))

static inline void init_ip_frags(struct ip_frags *ip_frags)
{
	ip_frags->nqueues = 0;
	INIT_LIST_HEAD(&ip_frags->lru_list);
	spin_lock_init(&ip_frags->lru_lock);
}

static inline void ip_frag_lru_del(struct frag_queue *q)
{
	spin_lock(&q->ip_frags->lru_lock);
	list_del_init(&q->lru_list);
	q->ip_frags->nqueues--;
	spin_unlock(&q->ip_frags->lru_lock);
}

static inline void ip_frag_lru_add(struct ip_frags *ip_frags,
				   struct frag_queue *q)
{
	spin_lock(&ip_frags->lru_lock);
	list_add_tail(&q->lru_list, &ip_frags->lru_list);
	ip_frags->nqueues++;
	spin_unlock(&ip_frags->lru_lock);
}

static inline void ip_frag_lru_move(struct frag_queue *q)
{
	spin_lock(&q->ip_frags->lru_lock);
	if (!list_empty(&q->lru_list))
		list_move_tail(&q->lru_list, &q->ip_frags->lru_list);
	spin_unlock(&q->ip_frags->lru_lock);
}

extern void ipv4_frags_init(void);
extern struct sk_buff *ipv4_defrag(struct sk_buff *skb, struct ip_frags *ip_frags);
/* head: the fragment 0 of the ipv4 fragments */
extern struct sk_buff *ipv4_get_skb_by_offset(struct sk_buff *head, int offset);
/* offset: this offset shoule be in the skb */
extern void *ipv4_get_data(struct sk_buff *skb, int offset);
extern int ipv4_copy_transport_head(void *data, struct sk_buff *head, int size);

static inline struct sk_buff *next_skb(struct sk_buff *skb, struct sk_buff *head)
{
	if (skb == head)
		return skb_shinfo(skb)->frag_list;
	else
		return skb->next;
}
#endif
