#include "hash.h"

void hash_init(struct hash_head *h)
{
	int i;

	for (i = 0; i < HASH_NR; i++) {
		skb_queue_head_init(&h->e[i].queue);
	}
}

int fetch_key(const struct sk_buff *skb, unsigned short *src, unsigned short *dst)
{
	unsigned char protocol;
	int len, port;
	unsigned char *t;
	unsigned char *p = skb->data;

	t = (unsigned char*)&len;
	*t = *((unsigned char *)(p + 14));

	len &= 0xf;
	len = len * 4;

	port = 14 + len;

	t = (unsigned char*)&protocol;
	*t = *((unsigned char *)(p + 23));

	if (protocol == 17 || protocol == 6) {
		t = (unsigned char*)src;
		*(t+1) = *((unsigned char *)(p + port));
		*t = *((unsigned char *)(p + port + 1));
		t = (unsigned char*)dst;
		*(t+1) = *((unsigned char *)(p + port + 2));
		*t = *((unsigned char *)(p + port + 3));
		return 1;
	}

	*src = *dst = 0;
	return 0;
}


int insert(struct hash_head *h, struct sk_buff *skb)
{
	unsigned short src, dst;
	int i;

	fetch_key(skb, &src, &dst);
	i = dst % HASH_NR;
	skb_queue_tail(&h->e[i].queue, skb);

	return i;
}
