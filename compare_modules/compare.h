#ifndef COMPARE_H
#define COMPARE_H

#include <linux/skbuff.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

enum {
	state_comparing,
	state_incheckpoint,
	state_failover,
};
extern uint32_t state;

struct compare_info {
	struct sk_buff *skb;
	struct ethhdr *eth;
	union {
		void *packet;
		struct iphdr *ip;
	};
	union {
		void *ip_data;
		struct tcphdr *tcp;
		struct udphdr *udp;
	};
	union {
		void *transport_data;
		void *tcp_data;
		void *udp_data;
	};
	unsigned int length;

	/* length: 32bytes */
	void *private_data;
};

/* It is protected by RCU, so don't sleep in all callbacks */
struct compare_ops {
	uint32_t (*compare)(struct compare_info *m, struct compare_info *s);
	uint32_t (*compare_one_packet)(struct compare_info *m, struct compare_info *s);
	uint32_t (*compare_fragment)(struct compare_info *m, struct compare_info *s);
	uint32_t (*compare_one_fragment)(struct compare_info *m, struct compare_info *s);
	void (*update_info)(void *info, void *data, uint32_t len, struct sk_buff *skb);
	void (*debug_print)(const struct compare_info *info, const void *data);
};

typedef struct compare_ops compare_ops_t;

#define		BYPASS_MASTER		0x01
#define		DROP_SLAVER		0x02
#define		SAME_PACKET		(BYPASS_MASTER | DROP_SLAVER)
#define		CHECKPOINT		0x80000000
#define		UPDATE_COMPARE_INFO	0x40000000

extern uint32_t compare_other_packet(void *m, void *s, int length);
extern wait_queue_head_t queue;

/* compare device */
extern int colo_dev_init(void);
extern void colo_dev_fini(void);

/* ipv4 */
extern uint32_t ipv4_compare_packet(struct compare_info *m,
				    struct compare_info *s);
extern void ipv4_update_compare_info(void *info, struct iphdr *ip,
				   struct sk_buff *skb);

extern int register_compare_ops(compare_ops_t *ops, unsigned short protocol);
extern int unregister_compare_ops(compare_ops_t *ops, unsigned short protocol);
extern uint32_t ipv4_transport_compare_fragment(struct sk_buff *m_head,
						struct sk_buff *s_head,
						int m_off, int s_off, int len);
extern uint32_t ipv4_compare_one_packet(struct compare_info *m, struct compare_info *s);

/* tcp */
extern void compare_tcp_init(void);
extern void compare_tcp_fini(void);

/* udp */
extern void compare_udp_init(void);
extern void compare_udp_fini(void);

#endif
