#include "hash.h"

void hash_init(struct hash_head *h)
{
	int i;
	
	for (i = 0; i < HASH_NR; i++) {
		h->e[i].qlen = 0;
		skb_queue_head_init(&h->e[i].queue);
	}	

	//for (i = 0; i < MAPSIZE; i++)
	//	h->map[i] = -1;
}

int fetch_key(const struct sk_buff *skb, unsigned short *src, unsigned short *dst)
{
	unsigned char protocol;
	int len, port;
	unsigned char *t;
	unsigned char *p = skb->data;

	t = &len;
	*t = *((unsigned char *)(p + 14));
		
	len &= 0xf;
	len = len * 4;

	port = 14 + len;

	t = &protocol;
	*t = *((unsigned char *)(p + 23));

	if (protocol == 17 || protocol == 6) {
		t = src;
		*(t+1) = *((unsigned char *)(p + port));
		*t = *((unsigned char *)(p + port + 1));	
		t = dst;
		*(t+1) = *((unsigned char *)(p + port + 2));
		*t = *((unsigned char *)(p + port + 3));
		return 1;
	}
	
	*src = *dst = 0;
	return 0;
	
}


int insert(struct hash_head *h, const struct sk_buff *skb)
{
	unsigned short src, dst;
	int i, m;

	fetch_key(skb, &src, &dst);
	//printk("dst:%u.", dst);
	i = dst % HASH_NR;
	//i = 0;
	//printk("i:%u.", i);
	//h->e[i].dst = dst;
	/*if (h->map[dst] != -1) {
		i = h->map[dst];
	} else {
		i = alloc_elem(h);
		h->e[i].dst = dst;
		h->map[dst] = i;
	}*/
	h->e[i].qlen++;
	__skb_queue_tail(&h->e[i].queue, skb);	

	return h->e[i].qlen;
}
