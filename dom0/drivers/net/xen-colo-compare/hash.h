#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

#define HASH_NR 	10000
#define MAPSIZE		65536
#define MAXQ		100

struct Q_elem {	
	//int dst; // ignore ip temporary, just use dst port.
	int qlen;
	struct sk_buff_head queue;
};

struct hash_head {
	struct Q_elem e[HASH_NR];
	//short map[MAPSIZE];
};

void hash_init(struct hash_head *h);
int insert(struct hash_head *h, const struct sk_buff *skb);
