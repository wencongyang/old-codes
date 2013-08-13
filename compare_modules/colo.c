#include "hash.h"
#include "comm.h"

enum {
	TCA_COLO_UNSPEC,
	TCA_COLO_IDX,
	TCA_COLO_FLAGS,
	__TCA_COLO_MAX,
};

//#define TCA_COLO_MAX	(__TCA_COLO_MAX - 1)
#define TCA_COLO_MAX 10

// flags
#define IS_MASTER	(1 << 0)

struct colo_idx {
	uint32_t this_idx;
	uint32_t other_idx;
};

/* qidsc: colo */
struct sched_data *master_queue = NULL;
struct sched_data *slaver_queue = NULL;
EXPORT_SYMBOL(master_queue);
EXPORT_SYMBOL(slaver_queue);

PTRFUN compare_update = NULL;
EXPORT_SYMBOL(compare_update);

static int colo_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct sched_data *q = qdisc_priv(sch);
	int index;
	struct Q_elem *m, *s;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	index = insert(&q->blo, skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	qdisc_bstats_update(sch, skb);

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (compare_update) {
		m = &master_queue->blo.e[index];
		s = &slaver_queue->blo.e[index];
		compare_update(m, s);
	}

	return NET_XMIT_SUCCESS;
}

static struct sk_buff *colo_dequeue(struct Qdisc* sch)
{
	struct sched_data *q = qdisc_priv(sch);
	struct sk_buff *skb;

	spin_lock(&q->qlock_rel);

	skb = __skb_dequeue(&q->rel);
	if (!(q->flags & IS_MASTER)) {
		while (likely(skb)) {
			/* Slaver: Free all packets. */
			sch->qstats.backlog -= qdisc_pkt_len(skb);
			kfree_skb(skb);
			skb = __skb_dequeue(&slaver_queue->rel);
		}
	}

	spin_unlock(&q->qlock_rel);

	if (skb)
		sch->qstats.backlog -= qdisc_pkt_len(skb);

	return skb;
}

static int colo_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct sched_data *q = qdisc_priv(sch);
	struct nlattr *tb[TCA_COLO_MAX + 1];
	int err;
	struct colo_idx *idx;
	uint32_t *flags;

	printk(KERN_DEBUG "master_init\n");
	err = nla_parse_nested(tb, TCA_COLO_MAX, opt, NULL);
	if (err)
		return err;

	if (!tb[TCA_COLO_IDX] || !tb[TCA_COLO_FLAGS]) {
		pr_err("missing parameter\n");
		return -EINVAL;
	}

	flags = nla_data(tb[TCA_COLO_FLAGS]);
	idx = nla_data(tb[TCA_COLO_IDX]);
	if (*flags & IS_MASTER) {
		pr_info("master_idx is: %d, slaver_idx is: %d\n", idx->this_idx, idx->other_idx);
		master_queue = q;
	} else {
		pr_info("master_idx is: %d, slaver_idx is: %d\n", idx->other_idx, idx->this_idx);
		slaver_queue = q;
	}

	hash_init(&q->blo);
	skb_queue_head_init(&q->rel);
	spin_lock_init(&q->qlock_rel);
	q->sch = sch;
	q->flags = *flags;

	return 0;
}

struct Qdisc_ops colo_qdisc_ops = {
	.id          =       "colo",
	.priv_size   =       sizeof(struct sched_data),
	.enqueue     =       colo_enqueue,
	.dequeue     =       colo_dequeue,
	.peek        =       qdisc_peek_head,
	.init        =       colo_init,
	.owner       =       THIS_MODULE,
};

static int __init colo_module_init(void)
{
	int ret;

	ret = register_qdisc(&colo_qdisc_ops);
	return ret;
}

static void __exit colo_module_exit(void)
{
	master_queue = NULL;
	slaver_queue = NULL;
	unregister_qdisc(&colo_qdisc_ops);
}
module_init(colo_module_init)
module_exit(colo_module_exit)
MODULE_LICENSE("GPL");
