typedef void (*PTRFUN)(struct hash_value *hash_value);

struct sched_data {
	struct hash_head *blo; /* packets not compared */
	struct sk_buff_head rel; /* packest compared successfully */
	struct Qdisc* sch;
	uint32_t flags;
};
