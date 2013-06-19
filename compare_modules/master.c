/*  sch_master.c defines "master" Qdisc. Packets sent from master VM will
 *  be dirrected to this module. This module puts all of these packets into
 *  a block queue, and then notifys the compare module for comparison.
 *  Compared successed packets will be moved to a release queue by compare
 *  module for releasing.
 *  YeWei - 2011/9/1
 */

#include "hash.h"
#include "comm.h"

struct sched_data *master_queue = NULL;
EXPORT_SYMBOL(master_queue);

PTRFUN m_compare_update = NULL;
EXPORT_SYMBOL(m_compare_update);

static int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}

static int master_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	int qlen;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	spin_lock(&master_queue->qlock_blo);
	qlen = insert(&master_queue->blo, skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	qdisc_bstats_update(sch, skb);
	spin_unlock(&master_queue->qlock_blo);

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (m_compare_update != NULL)
		m_compare_update(qlen);

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *master_dequeue(struct Qdisc* sch)
{
	struct sk_buff *skb;

	spin_lock(&master_queue->qlock_rel);

	skb = __skb_dequeue(&master_queue->rel);

	spin_unlock(&master_queue->qlock_rel);

	if (likely(skb != NULL)) {
		sch->qstats.backlog -= qdisc_pkt_len(skb);
	}

	return skb;
}

static int master_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct sched_data *q = qdisc_priv(sch);

	printk(KERN_DEBUG "master_init\n");
	master_queue = q;
	hash_init(&master_queue->blo);
	skb_queue_head_init(&master_queue->rel);
	skb_queue_head_init(&master_queue->nfs);
	spin_lock_init(&q->qlock_blo);
	spin_lock_init(&q->qlock_rel);
	spin_lock_init(&q->qlock_nfs);
	master_queue->sch = sch;

	return 0;
}

struct Qdisc_ops master_qdisc_ops = {
	.id          =       "master",
	.priv_size   =       sizeof(struct sched_data),
	.enqueue     =       master_enqueue,
	.dequeue     =       master_dequeue,
	.peek        =       qdisc_peek_head,
	.init        =       master_init,
	.owner       =       THIS_MODULE,
};

static int __init master_module_init(void)
{
	return register_qdisc(&master_qdisc_ops);
}

static void __exit master_module_exit(void)
{
	master_queue = NULL;
	unregister_qdisc(&master_qdisc_ops);
}
module_init(master_module_init)
module_exit(master_module_exit)
MODULE_LICENSE("GPL");
