#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

#define HASH_NR 	10000

#define IS_MASTER	(1 << 0)

struct colo_idx {
	uint32_t master_idx;
	uint32_t slaver_idx;
};

struct hash_head;

struct hash_value {
	struct sk_buff_head master_queue;
	struct sk_buff_head slaver_queue;
	struct hash_head *head;
	uint32_t m_last_seq;
	uint32_t s_last_seq;
};

struct hash_head {
	struct hash_value e[HASH_NR];
	struct colo_idx idx;
	struct sk_buff_head wait_for_release;
	struct sched_data *master_data;
	struct sched_data *slaver_data;
	struct list_head list;
	int master:1, slaver:1;
};

void hash_init(struct hash_head *h);
struct hash_value *insert(struct hash_head *h, struct sk_buff *skb, uint32_t flags);
