typedef void (*PTRFUN)(int);

struct sched_data {
	struct hash_head blo; /* packets not compared */
	struct sk_buff_head rel; /* packest compared successfully */
	struct sk_buff_head nfs; /* packets to nfs server */
	struct Qdisc* sch;

	spinlock_t qlock_blo;
	spinlock_t qlock_rel;
	spinlock_t qlock_nfs;
};

static inline int skb_remove_foreign_references(struct sk_buff *skb)
{
	return !skb_linearize(skb);
}
