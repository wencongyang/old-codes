typedef void (*PTRFUN)(void);

struct sched_data {
	struct hash_head blo; /* packets not compared */
	struct sk_buff_head rel; /* packest compared successfully */
	struct Qdisc* sch;

	spinlock_t qlock_blo;
	spinlock_t qlock_rel;
};

static inline int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}
