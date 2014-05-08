/*  sch_master.c defines "master" Qdisc. Packets sent from master VM will
 *  be dirrected to this module. This module puts all of these packets into
 *  a block queue, and then notifys the compare module for comparison.
 *  Compared successed packets will be moved to a release queue by compare
 *  module for releasing. 
 *  YeWei - 2011/9/1
 */

#include "hash.h"

typedef void (*PTRFUN)();

struct sched_data {
	struct hash_head blo; /* packets not compared */
	struct sk_buff_head rel; /* packest compared successfully */
	struct sk_buff_head nfs; /* packets to nfs server */
	struct Qdisc* sch;

	spinlock_t qlock_blo;
	spinlock_t qlock_rel;
	spinlock_t qlock_nfs;
};
struct sched_data *master_queue = NULL;
EXPORT_SYMBOL(master_queue);

PTRFUN m_compare_update = NULL;
EXPORT_SYMBOL(m_compare_update);

struct timestampe {
	unsigned long long arrive;
	unsigned short dst;
};
struct timestampe tsm_list[100];
int tsm_len = 0;
EXPORT_SYMBOL(tsm_list);
EXPORT_SYMBOL(tsm_len);

extern unsigned long long sched_clock(void);

static int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}

static void get_udp_info(const unsigned char* p, unsigned char *protocol, 
			unsigned int *XID, unsigned int *stamp, 
			unsigned short *src_port, unsigned short *dst_port)
{
	unsigned char *t;

	t = protocol;
	*t = *((unsigned char *)(p + 23));

	if (*protocol == 17) {// UDP
		t = src_port;
		*(t+1) = *((unsigned char *)(p + 34));
		*t = *((unsigned char *)(p + 35));
		
		t = dst_port;
		*(t+1) = *((unsigned char *)(p + 36));
		*t = *((unsigned char *)(p + 37));
		
		t = XID;
		*(t+3) = *((unsigned char *)(p + 42));
		*(t+2) = *((unsigned char *)(p + 43));
		*(t+1) = *((unsigned char *)(p + 44));
		*t = *((unsigned char *)(p + 45));

		t = stamp;
		*(t+3) = *((unsigned char *)(p + 74));
		*(t+2) = *((unsigned char *)(p + 75));
		*(t+1) = *((unsigned char *)(p + 76));
		*t = *((unsigned char *)(p + 77));
	}
}

static int is_nfs_pkt(const struct sk_buff *p)
{
	unsigned char *buf, protocol;
	unsigned short src_port, dst_port;
	unsigned short XID, stamp;
	unsigned short eth_type;
	unsigned char *t;

	buf = p->data;
	
	t = &eth_type;
	*(t+1) = *((unsigned char *)(buf + 12));
	*t = *((unsigned char *)(buf + 13));
	if (eth_type == 0x0806) //arp
		return 1;
	
	get_udp_info(buf, &protocol, &XID, &stamp, &src_port, &dst_port);
	
	return protocol == 17;
}

int count = 0;
static int master_enqueue(struct sk_buff *skb, struct Qdisc* sch)
{
	int qlen;
	unsigned short src;

	if (!skb_remove_foreign_references(skb)) {
		printk(KERN_DEBUG "error removing foreign ref\n");
		return qdisc_reshape_fail(skb, sch);
	}

	/* nfs pkt release directly */
	/*if ( is_nfs_pkt(skb) ) {
		spin_lock(&master_queue->qlock_rel);
		__skb_queue_tail(&master_queue->rel, skb);
		//printk("HA_compare: mster pkt, %d\n", ++count);
		sch->qstats.backlog += qdisc_pkt_len(skb);
		__qdisc_update_bstats(sch, qdisc_pkt_len(skb));
		spin_unlock(&master_queue->qlock_rel);
	
		netif_schedule_queue(master_queue->sch->dev_queue);
		return NET_XMIT_SUCCESS;
	}*/

	spin_lock(&master_queue->qlock_blo);
	//printk("HA_compare: not nfs pkt\n");
	//__skb_queue_tail(&master_queue->blo, skb);
	qlen = insert(&master_queue->blo, skb);
	sch->qstats.backlog += qdisc_pkt_len(skb);
	//__qdisc_update_bstats(sch, qdisc_pkt_len(skb));
	qdisc_bstats_update(sch, skb);

	if (tsm_len < 100) {
		tsm_list[tsm_len].arrive = sched_clock() / 1000;
		fetch_key(skb, &src, &tsm_list[tsm_len].dst);
		tsm_len++;
	}

	spin_unlock(&master_queue->qlock_blo);
	
	/*
	 *  Notify the compare module a new packet arrives.
	 */
	if (m_compare_update != NULL)
		m_compare_update(qlen);

	return NET_XMIT_SUCCESS;
}

int count_tot = 0;
static struct sk_buff *master_dequeue(struct Qdisc* sch)
{
	struct sk_buff *skb;

	spin_lock(&master_queue->qlock_rel);

	skb = __skb_dequeue(&master_queue->rel);

	spin_unlock(&master_queue->qlock_rel);

	if (likely(skb != NULL)) {
		//printk("HA_compare: ifb0 release %d\n", ++count_tot);
		sch->qstats.backlog -= qdisc_pkt_len(skb);
	}

	//netif_schedule_queue(master_queue->sch->dev_queue);
	return skb;
}

static int master_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct sched_data *q = qdisc_priv(sch);
	
	printk(KERN_DEBUG "master_init\n");
	master_queue = q;
	//skb_queue_head_init(&master_queue->blo);
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
