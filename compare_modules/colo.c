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

/* qidsc: colo */

struct list_head queue = LIST_HEAD_INIT(queue);
spinlock_t queue_lock;

PTRFUN compare_update = NULL;
EXPORT_SYMBOL(compare_update);

struct hash_head *colo_hash_head;
EXPORT_SYMBOL(colo_hash_head);

static struct hash_head *alloc_hash(struct colo_idx *idx, int flags)
{
	struct hash_head *h;

	spin_lock(&queue_lock);
	list_for_each_entry(h, &queue, list) {
		if (h->idx.master_idx != idx->master_idx ||
		    h->idx.slaver_idx != idx->slaver_idx)
			continue;

		if (flags & IS_MASTER)
			if (h->master)
				h = ERR_PTR(-EBUSY);
			else
				h->master = 1;
		else
			if (h->slaver)
				h = ERR_PTR(-EBUSY);
			else
				h->slaver = 1;

		goto out;
	}

	h = kmalloc(sizeof(struct hash_head), GFP_ATOMIC);
	if (!h) {
		h = ERR_PTR(-ENOMEM);
		goto out;
	}

	hash_init(h);

	h->idx = *idx;
	if (flags & IS_MASTER)
		h->master = 1;
	else
		h->slaver = 1;
	list_add_tail(&h->list, &queue);

out:
	if (colo_hash_head)
		pr_warn("colo_hash_head: %p, h: %p\n", colo_hash_head, h);
	colo_hash_head = h;
	spin_unlock(&queue_lock);
	return h;
}

static int colo_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	struct sched_data *q = qdisc_priv(sch);
	int index;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	index = insert(q->blo, skb, q->flags);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	qdisc_bstats_update(sch, skb);

	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (compare_update)
		compare_update(q->blo, index);

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
			skb = __skb_dequeue(&q->rel);
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

	pr_debug("colo init\n");
	err = nla_parse_nested(tb, TCA_COLO_MAX, opt, NULL);
	if (err)
		return err;

	if (!tb[TCA_COLO_IDX] || !tb[TCA_COLO_FLAGS]) {
		pr_err("missing parameter\n");
		return -EINVAL;
	}

	flags = nla_data(tb[TCA_COLO_FLAGS]);
	idx = nla_data(tb[TCA_COLO_IDX]);
	if (!(*flags & IS_MASTER)) {
		idx->master_idx = idx->master_idx ^ idx->slaver_idx;
		idx->slaver_idx = idx->master_idx ^ idx->slaver_idx;
		idx->master_idx = idx->master_idx ^ idx->slaver_idx;
	}
	pr_info("master_idx is: %d, slaver_idx is: %d, flags: %02x\n", idx->master_idx, idx->slaver_idx, *flags);

	q->blo = alloc_hash(idx, *flags);
	if (IS_ERR(q->blo))
		return PTR_ERR(q->blo);

	if (*flags & IS_MASTER)
		q->blo->master_data = q;
	else
		q->blo->slaver_data = q;
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
	spin_lock_init(&queue_lock);
	return register_qdisc(&colo_qdisc_ops);
}

static void __exit colo_module_exit(void)
{
	unregister_qdisc(&colo_qdisc_ops);
}
module_init(colo_module_init)
module_exit(colo_module_exit)
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
