#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

#define HASH_NR 	1000

struct Q_elem {	
	struct sk_buff_head queue;
	uint32_t last_seq;
};

struct hash_head {
	struct Q_elem e[HASH_NR];
};

void hash_init(struct hash_head *h);
void insert(struct hash_head *h, struct sk_buff *skb);
