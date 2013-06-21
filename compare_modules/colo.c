#include "hash.h"
#include "comm.h"

/* qidsc: master */
struct sched_data *master_queue = NULL;
struct sched_data *slaver_queue = NULL;
EXPORT_SYMBOL(master_queue);

PTRFUN m_compare_update = NULL;
EXPORT_SYMBOL(m_compare_update);

static int master_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	int index;
	struct Q_elem *m, *s;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	index = insert(&master_queue->blo, skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	qdisc_bstats_update(sch, skb);

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (m_compare_update != NULL && slaver_queue != NULL) {
		m = &master_queue->blo.e[index];
		s = &slaver_queue->blo.e[index];
		m_compare_update(m, s);
	}

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
	spin_lock_init(&q->qlock_rel);
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

/* qdisc: slaver */
EXPORT_SYMBOL(slaver_queue);

PTRFUN s_compare_update = NULL;
EXPORT_SYMBOL(s_compare_update);

static int slaver_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	int index;
	struct Q_elem *m, *s;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	index = insert(&slaver_queue->blo, skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	qdisc_bstats_update(sch, skb);

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (s_compare_update != NULL && master_queue != NULL) {
		m = &master_queue->blo.e[index];
		s = &slaver_queue->blo.e[index];
		s_compare_update(m, s);
	}

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *slaver_dequeue(struct Qdisc* sch)
{
	struct sk_buff *skb;

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

	spin_unlock(&slaver_queue->qlock_rel);

	return NULL;
}

static int slaver_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct sched_data *q = qdisc_priv(sch);

	printk(KERN_DEBUG "slaver_init\n");
	slaver_queue = q;
	hash_init(&slaver_queue->blo);
	skb_queue_head_init(&slaver_queue->rel);
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

static int __init colo_module_init(void)
{
	int ret;

	ret = register_qdisc(&master_qdisc_ops);
	if (ret)
		return ret;

	ret = register_qdisc(&slaver_qdisc_ops);
	if (ret) {
		unregister_qdisc(&master_qdisc_ops);
		return ret;
	}

	return 0;
}

static void __exit colo_module_exit(void)
{
	master_queue = NULL;
	slaver_queue = NULL;
	unregister_qdisc(&master_qdisc_ops);
	unregister_qdisc(&slaver_qdisc_ops);
}
module_init(colo_module_init)
module_exit(colo_module_exit)
MODULE_LICENSE("GPL");
