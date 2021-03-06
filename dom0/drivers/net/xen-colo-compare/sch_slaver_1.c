/*  sch_slaver.c defines "slaver" Qdisc. Packets sent from slaver VM will
 *  be dirrected to this module. This module puts all of these packets into
 *  a block queue, and then notifys the compare module for comparison.
 *  Compared successed packets will be moved to a release queue by compare
 *  module, and the enqueue routine will free those packets. 
 *  YeWei - 2011/9/1
 */
#include "hash.h"

typedef void (*PTRFUN)();

struct sched_data {
	struct hash_head blo; /* packets not compared */
	struct sk_buff_head rel; /* packets compared successfully */
	struct sk_buff_head nfs; /* packets to nfs server */
	struct Qdisc *sch;

	spinlock_t qlock_blo;
	spinlock_t qlock_rel;
	spinlock_t qlock_nfs;
};
struct sched_data *slaver_queue = NULL;
EXPORT_SYMBOL(slaver_queue);

extern struct sched_data *master_queue;

PTRFUN s_compare_update = NULL;
EXPORT_SYMBOL(s_compare_update);

static int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}

int count = 0;
static int slaver_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	int qlen;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	spin_lock(&slaver_queue->qlock_blo);
	//__skb_queue_tail(&slaver_queue->blo, skb);
	qlen = insert(&slaver_queue->blo, skb);	
	sch->qstats.backlog += qdisc_pkt_len(skb);
	//__qdisc_update_bstats(sch, qdisc_pkt_len(skb));
	qdisc_bstats_update(sch, skb);

	spin_unlock(&slaver_queue->qlock_blo);

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (s_compare_update != NULL)
		s_compare_update(qlen);

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *slaver_dequeue(struct Qdisc* sch)
{
	struct sk_buff *skb;

	//return NULL;
		
	spin_lock(&slaver_queue->qlock_rel);
	
	skb = __skb_dequeue(&slaver_queue->rel);
	

	while (likely(skb!=NULL)) {
		/*
		 * Free the packets, sch_slaver needs not to release packets.
		 */
		sch->qstats.backlog -= qdisc_pkt_len(skb);	
		kfree_skb(skb);
		skb = __skb_dequeue(&slaver_queue->rel);
	}

	/* Release pakcets to nfs server  */
	//skb = __skb_dequeue(&slaver_queue->nfs);

	//if (likely(skb != NULL))
	//	sch->qstats.backlog -= qdisc_pkt_len(skb);

	spin_unlock(&slaver_queue->qlock_rel);
	
	//return skb;
	return NULL;
}

static int slaver_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct sched_data *q = qdisc_priv(sch);
	
	printk(KERN_DEBUG "slaver_init\n");
	slaver_queue = q;
	//skb_queue_head_init(&slaver_queue->blo);
	hash_init(&slaver_queue->blo);
	skb_queue_head_init(&slaver_queue->rel);
	skb_queue_head_init(&slaver_queue->nfs);
	spin_lock_init(&q->qlock_blo);
	spin_lock_init(&q->qlock_nfs);
	spin_lock_init(&q->qlock_rel);
	slaver_queue->sch = sch;

	return 0;
}

struct Qdisc_ops slaver_qdisc_ops = {
	.id          =       "slaver",
	.priv_size   =       sizeof(struct sched_data),
	.enqueue     =       slaver_enqueue,
	.dequeue     =       slaver_dequeue,
	.peek        =       qdisc_peek_head,
	.init        =       slaver_init,
	.owner       =       THIS_MODULE,
};

static int __init slaver_module_init(void)
{
	return register_qdisc(&slaver_qdisc_ops);
}

static void __exit slaver_module_exit(void)
{
	slaver_queue = NULL;
	unregister_qdisc(&slaver_qdisc_ops);
}
module_init(slaver_module_init)
module_exit(slaver_module_exit)
MODULE_LICENSE("GPL");
