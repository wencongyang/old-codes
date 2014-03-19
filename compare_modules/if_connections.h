#ifndef COLO_HASH_H
#define COLO_HASH_H

#include <linux/skbuff.h>
#include <linux/types.h>

#define HASH_NR 	10000

#define IS_MASTER	(1 << 0)
#define DESTROY		(1 << 16)

struct colo_idx {
	uint32_t master_idx;
	uint32_t slaver_idx;
};

struct connection_keys {
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

struct if_connections;
struct colo_sched_data;

struct connect_info {
	struct sk_buff_head master_queue;
	struct sk_buff_head slaver_queue;
	struct if_connections *ics;

	struct connection_keys key;
	struct list_head list;
	struct list_head compare_list;
	uint32_t state;
	wait_queue_head_t wait;

	/* transport layer defines it */
	uint32_t m_info[32];
	uint32_t s_info[32];
};

/* state */
#define IN_COMPARE	(1 << 0)
#define IN_DESTROY	(1 << 1)

struct if_connections {
	struct list_head entry[HASH_NR];
	struct colo_idx idx;
	struct sk_buff_head wait_for_release;
	struct colo_sched_data *master_data;
	struct colo_sched_data *slaver_data;
	struct list_head list;
	int master:1, slaver:1;
};

extern void init_if_connections(struct if_connections *ics);
extern struct connect_info *insert(struct if_connections *ics,
				   struct sk_buff *skb,
				   uint32_t flags);
extern void destroy_connections(struct if_connections *ics, uint32_t flags);

#endif
