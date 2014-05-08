#include <linux/module.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <net/pkt_sched.h>

#define HASH_NR 	1000
#define MAPSIZE		65536
#define MAXQ		100

struct Q_elem {	
	//int dst; // ignore ip temporary, just use dst port.
	int qlen;
	struct sk_buff_head queue;
	uint32_t last_jiffies;
};

struct hash_head {
	struct Q_elem e[HASH_NR];
	//short map[MAPSIZE];
};

void hash_init(struct hash_head *h);
int insert(struct hash_head *h, const struct sk_buff *skb);
int fetch_key(const struct sk_buff *skb, unsigned short *src, unsigned short *dst);
