#ifndef COLO_HASH_H
#define COLO_HASH_H

#include <linux/skbuff.h>
#include <linux/types.h>

#define HASH_NR 	10000

#define IS_MASTER	(1 << 0)

struct colo_idx {
	uint32_t master_idx;
	uint32_t slaver_idx;
};

struct flow_keys {
	/* (src,dst) must be grouped, in the same way than in IP header */
	__be32 src;
	__be32 dst;
	union {
		__be32 ports;
		__be16 port16[2];
	};
	u16 thoff;
	u8 ip_proto;
};

struct hash_head;
struct sched_data;

struct connect_info {
	struct sk_buff_head master_queue;
	struct sk_buff_head slaver_queue;
	struct hash_head *head;

	struct flow_keys key;
	struct list_head list;
	struct list_head compare_list;

	/* transport layer defines it */
	uint32_t m_info[8];
	uint32_t s_info[8];
};

struct hash_head {
	struct list_head entry[HASH_NR];
	struct colo_idx idx;
	struct sk_buff_head wait_for_release;
	struct sched_data *master_data;
	struct sched_data *slaver_data;
	struct list_head list;
	int master:1, slaver:1;
};

void hash_init(struct hash_head *h);
struct connect_info *insert(struct hash_head *h, struct sk_buff *skb, uint32_t flags);

#endif
