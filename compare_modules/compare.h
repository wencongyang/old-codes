#ifndef COMPARE_H
#define COMPARE_H

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
		void *transfer_data;
		void *tcp_data;
		void *udp_data;
	};
	unsigned int length;

	/* only for tcp */
	unsigned int last_seq;
};

struct compare_ops {
	int (*compare)(struct compare_info *m, struct compare_info *s);
	void (*debug_print)(void *data);
};

typedef struct compare_ops compare_ops_t;

#define		BYPASS_MASTER		0x01
#define		DROP_SLAVER		0x02
#define		SAME_PACKET		0x04

extern int register_compare_ops(compare_ops_t *ops, unsigned short protocol);
extern int unregister_compare_ops(compare_ops_t *ops, unsigned short protocol);
extern int compare_other_packet(void *m, void *s, int length);

/* tcp */
extern bool ignore_ack_packet;
extern bool ignore_retransmitted_packet;
extern bool compare_tcp_data;
extern bool ignore_tcp_window;
extern bool ignore_ack_difference;

extern void compare_tcp_init(void);
extern void compare_tcp_fini(void);

/* udp */
extern void compare_udp_init(void);
extern void compare_udp_fini(void);

#endif
