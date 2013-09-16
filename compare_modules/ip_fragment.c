#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <net/inet_frag.h>

#include "ip_fragment.h"

void kill_frag_queue(struct frag_queue *q)
{
	if (del_timer(&q->timer))
		atomic_dec(&q->refcnt);

	if (!(q->last_in & INET_FRAG_COMPLETE)) {
		fq_unlink(q, q->hb);
		atomic_dec(&q->refcnt);
		q->last_in |= INET_FRAG_COMPLETE;
	}
}

void destroy_frag_queue(struct frag_queue *q)
{
	struct sk_buff *skb;

	WARN_ON(!(q->last_in & INET_FRAG_COMPLETE));
	WARN_ON(del_timer(&q->timer) != 0);

	skb = q->fragments;
	while (skb) {
		struct sk_buff *next = skb->next;

		/* We can see skb only when timer expires */
		kfree_skb(skb);
		skb = next;
	}
}
