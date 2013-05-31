/*  When a packet received by sch_master module or sch_slaver module,
 *  the function update() will be involved. This function will peek a
 *  packet from two block queues respectively, then compare these two
 *  packets. If they are identical, they will be moved to two release
 *  queue respectively, otherwise, all packets on block queues will be
 *  freed.
 *  Yewei - 2011/9/1
 */


#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/semaphore.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <net/pkt_sched.h>
#include <asm/ioctl.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/if_arp.h>
#include "hash.h"

bool ignore_id = 1;
module_param(ignore_id, bool, 0644);
MODULE_PARM_DESC(ignore_id, "bypass id difference");

bool ignore_ack_packet = 1;
module_param(ignore_ack_packet, bool, 0644);
MODULE_PARM_DESC(ignore_ack_packet, "bypass ack only packet");

bool ignore_retransmitted_packet = 1;
module_param(ignore_retransmitted_packet, bool, 0644);
MODULE_PARM_DESC(ignore_retransmitted_packet, "bypass retransmitted packets");

typedef void (*PTRFUN)(int id);
int cmp_open(struct inode*, struct file*);
int cmp_release(struct inode*, struct file*);
long cmp_ioctl(struct file*, unsigned int, unsigned long);
unsigned short last_id = 0;
int fail = 0;

#define COMP_IOC_MAGIC 		'k'
#define COMP_IOCTWAIT 		_IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTSUSPEND 	_IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME 	_IO(COMP_IOC_MAGIC, 2)

struct proc_dir_entry* proc_entry;
struct statistic_data {
	unsigned int _update;   	// call counts of update()
	unsigned int _update_m; 	// call counts of update() from master,
						// also means number of enqueue skbs.
	unsigned int _update_s; 	// call counts of update() from slaver,
						// also means number of enqueue skbs.
	unsigned int _update_eff;	// time of update() do comparasion really
	unsigned int _loops_tot;	// totally loops time
	//unsigned int _loops_avg;	// average loops each update()
	unsigned int _loops_last;	// last loops in update()
} statis;

struct sched_data {
	struct hash_head blo;
	struct sk_buff_head rel;
	struct sk_buff_head nfs; /* packets to nfs server */
	struct Qdisc *sch;

	spinlock_t qlock_blo;
	spinlock_t qlock_rel;
	spinlock_t qlock_nfs;
};

struct sk_buff_head wait_for_release;
spinlock_t wqlock;

struct file_operations cmp_fops = {
	.owner = THIS_MODULE,
	.open = cmp_open,
	.unlocked_ioctl = cmp_ioctl,
	.release = cmp_release,
};

struct _cmp_dev {
	struct semaphore sem; /* only one client can open this device */
	struct cdev cdev;
} cmp_dev;

extern struct sched_data *master_queue;
extern struct sched_data *slaver_queue;
extern PTRFUN s_compare_update;
extern PTRFUN m_compare_update;
static void clear_slaver_queue(void);
static void move_master_queue(void);
static void release_queue(void);
void update(int id);

wait_queue_head_t queue;
int cmp_major=0, cmp_minor=0;
#define HASTATE_PENDING_NR	0
#define HASTATE_INCHECKPOINT_NR	1
#define HASTATE_RUNNING_NR	2

unsigned long int state = 0;
unsigned int same_count = 0;

static int cmp_setup_cdev(struct _cmp_dev *dev) {
	int err, devno = MKDEV(cmp_major, cmp_minor);

	cdev_init(&dev->cdev, &cmp_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &cmp_fops;
	err = cdev_add(&dev->cdev, devno, 1);

	if (err) {
		printk(KERN_WARNING"HA_compare: Error %d adding devices.\n", err);
		return -1;
	}

	return 0;
}

int cmp_open(struct inode *inode, struct file *filp)
{
	struct _cmp_dev *dev;

	dev = container_of(inode->i_cdev, struct _cmp_dev, cdev);
	/* try to get the mutext, thus only one client can open this dev */
	if (down_trylock(&dev->sem)) {
		printk(KERN_NOTICE "HA_compare: another client allready opened this dev.\n");
		return -1;
	}

	printk(KERN_NOTICE "HA_compare: open successfully.\n");
	filp->private_data = dev;
	return 0;
}

int cmp_release(struct inode *inode, struct file *filp)
{
	struct _cmp_dev *dev;

	dev = container_of(inode->i_cdev, struct _cmp_dev, cdev);
	up(&dev->sem);
	printk(KERN_NOTICE "HA_compare: close.\n");

	return 0;
}

int rel_count = 0;
long cmp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch(cmd) {
	case COMP_IOCTWAIT:
		clear_bit(HASTATE_INCHECKPOINT_NR, &state);
		/* wait for a new checkpoint */
		if (fail) {
			set_bit(HASTATE_INCHECKPOINT_NR, &state);
			return -2;
		}
#if 1
		ret = wait_event_interruptible_timeout(queue, test_bit(HASTATE_PENDING_NR, &state), 10);
		if (ret == 0)
			return -ETIME;

		if (ret < 0)
			return -ERESTART;
#else
		if (wait_event_interruptible(queue, state&HASTATE_PENDING))
			return -ERESTART;
#endif

		/*
		 *  A new checkpoint starts, block input packets to VMs.
		 */
		clear_bit(HASTATE_PENDING_NR, &state);

		if (fail) {
			set_bit(HASTATE_INCHECKPOINT_NR, &state);
			return -2;
		}

		printk(KERN_NOTICE "HA_compare: --------start a new checkpoint.\n");

		break;
	case COMP_IOCTSUSPEND:
		/*  Both side suspend the VM, at this point, no packets will
		 *  send out from VM, so block skb queues(master&slaver) are
		 *  stable. Move master block queue to a temporary queue, then
		 *  they will be released when checkpoint ends. For slaver
		 *  block queue, just drop them.
		 */
		printk(KERN_NOTICE "HA_compare: --------both side suspended.\n");

		move_master_queue();
		clear_slaver_queue();
		break;
	case COMP_IOCTRESUME:
		/*
		 *  Checkpoint finish, relese skb in temporary queue
		 */
		printk(KERN_NOTICE "HA_compare: --------checkpoint finish.\n");
		release_queue();
		rel_count = 0;

		break;
	}

	return 0;
}

static void debug_print_packet(const unsigned char *n, unsigned int doff)
{
	int i, j;

	printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
	printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
		n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]);
	printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\n",
		n[16], n[17], n[18], n[19]);

	/* TCP options */
	for (i = 20; i < doff; i++) {
		if (n[i] == 0)
			break;

		if (n[i] == 1) {
			/* nop */
			printk(KERN_DEBUG "HA_compare: nop\n");
			continue;
		}

		printk(KERN_DEBUG "HA_compare:");
		for (j = i; j < i + n[i+1]; j++) {
			printk(KERN_CONT " %02x", (unsigned int)n[j]);
		}
		printk(KERN_CONT "\n");

		i += n[i+1] - 1;
	}
}

static void debug_print_ip(const struct iphdr *ip)
{
	unsigned short len = htons(ip->tot_len);
	unsigned short id = htons(ip->id);
	unsigned char protocol = ip->protocol;
	void *packet = (char *)ip + ip->ihl * 4;
	unsigned short src_port, dst_port;

	printk("HA_compare:[IP]len = %u, id= %u.\n", len, id);

	if (protocol == IPPROTO_TCP) { // TCP
		struct tcphdr *tcp = packet;
		unsigned int ack, seq;
		unsigned int doff;

		src_port = htons(tcp->source);
		dst_port = htons(tcp->dest);
		ack = htonl(tcp->ack_seq);
		seq = htonl(tcp->seq);
		printk(KERN_DEBUG "HA_compare:[TCP] src=%u, dst=%u, seq = %u,"
					" ack=%u\n", src_port, dst_port, seq,
					ack);

		doff = tcp->doff * 4;
		debug_print_packet(packet, doff);

	} else if (protocol == IPPROTO_UDP) { // UDP
		struct udphdr *udp = packet;

		src_port = htons(udp->source);
		dst_port = htons(udp->dest);
		printk("HA_compare:[UDP] src=%u, dst=%u\n", src_port, dst_port);
	} else
		printk("HA_compare: unkown protocol: %u\n", protocol);
}

struct arp_reply {
	unsigned char		ar_sha[ETH_ALEN];
	unsigned char		ar_sip[4];
	unsigned char		ar_tha[ETH_ALEN];
	unsigned char		ar_tip[4];
};

static void debug_print_arp(const struct arphdr *arp)
{
	struct arp_reply *temp;

	printk("HA_compare:[ARP] ar_hrd=%u, ar_pro=%u\n",
		htons(arp->ar_hrd), htons(arp->ar_pro));
	printk("HA_compare:[ARP] ar_hln=%u, ar_pln=%u, ar_op=%u\n",
		arp->ar_hln, arp->ar_pln, htons(arp->ar_op));
	if (htons(arp->ar_op) == ARPOP_REPLY) {
		temp = (struct arp_reply *)((char*)arp + sizeof(struct arphdr));
		printk("HA_compare:[ARP] ar_sha: %pM, ar_sip: %pI4\n", temp->ar_sha, temp->ar_sip);
		printk("HA_compare:[ARP] ar_tha: %pM, ar_tip: %pI4\n", temp->ar_tha, temp->ar_tip);
	}
}

static void reset_compare_status(void)
{
	same_count = 0;
}

/* compare_xxx_packet() returns:
 *   0: do a new checkpoint
 *   1: bypass the packet from master,
 *   2: drop the packet from slaver
 *   3: bypass the packet from master, and drop the packet from slaver
 */

#define		BYPASS_MASTER		0x01
#define		DROP_SLAVER		0x02
#define		SAME_PACKET		0x04

struct compare_info {
	struct sk_buff *skb;
	struct ethhdr *eth;
	union {
		void *packet;
		struct iphdr *ip;
	};
	union {
		void *ip_packet;
		struct tcphdr *tcp;
		struct udphdr *udp;
	};
	union {
		void *tcp_packet;
		void *udp_packet;
	};
	unsigned int length;

	/* only for tcp */
	unsigned int last_seq;
};

static void print_debuginfo(struct compare_info *m, struct compare_info *s)
{
	printk("HA_compare: same=%u, last_id=%u, last_seq=%u\n", same_count, last_id, m->last_seq);
	printk(KERN_DEBUG "HA_compare: Master pkt:\n");
	debug_print_ip(m->ip);
	printk(KERN_DEBUG "HA_compare: Slaver pkt:\n");
	debug_print_ip(s->ip);
}

static int
compare_other_packet(void *m, void *s, int length)
{
	return memcmp(m, s, length) ? 0 : SAME_PACKET;
}

static int
compare_arp_packet(struct compare_info *m, struct compare_info *s)
{
	if (m->length != s->length)
		return 0;

	/* TODO */
	return compare_other_packet(m->packet, s->packet, m->length);
}

static int
compare_tcp_packet(struct compare_info *m, struct compare_info *s)
{
	int m_len, s_len;
	unsigned int m_seq, s_seq;
	int ret = 0;

#define compare(elem)							\
	if (unlikely(m->tcp->elem != s->tcp->elem)) {			\
		pr_warn("HA_compare: tcp header's %s is different\n",	\
			#elem);						\
		return 0;						\
	}

	/* source port and dest port*/
	compare(source);
	compare(dest);

	m_len = m->length - m->tcp->doff * 4;
	s_len = s->length - s->tcp->doff * 4;
	m_seq = htonl(m->tcp->seq);
	s_seq = htonl(s->tcp->seq);

	/* Sequence Number */
	if (m->tcp->syn) {
		compare(seq);
		m->last_seq = m_seq;
	} else {

		if (ignore_retransmitted_packet) {
			if ((m_len != 0 && m_seq == m->last_seq) ||
			    ((m_seq - m->last_seq) & (1<<31)))
				/* retransmitted packets */
				ret |= BYPASS_MASTER;
			if ((s_len != 0 && s_seq == m->last_seq) ||
			    ((s_seq - m->last_seq) & (1<<31)))
				/* retransmitted packets */
				ret |= DROP_SLAVER;
		}

		if (ret)
			goto out;

		compare(seq);
	}

	/* flags */
	if(memcmp((char *)m->tcp+13, (char *)s->tcp+13, 1)) {
		pr_warn("HA_compare: tcp header's flags is different\n");
		return 0;
	}

	if (ignore_ack_packet) {
		if (m_len == 0 && s_len != 0)
			ret |= BYPASS_MASTER;

		if (m_len != 0 && s_len == 0)
			ret |= DROP_SLAVER;
	}

	if (!ret && m_len != 0)
		m->last_seq = m_seq;

	/* Sequence Number */
	compare(seq);

	/* data offset */
	compare(doff);

	/* tcp window size */
	compare(window);

	/* Acknowledgment Number */
	if (m->tcp->ack) {
		compare(ack_seq);
	}

	if (m_len != 0 && s_len != 0) {
		m->tcp_packet = m->ip_packet + m->tcp->doff * 4;
		s->tcp_packet = s->ip_packet + s->tcp->doff * 4;
		ret = compare_other_packet(m->tcp_packet, s->tcp_packet, min(m_len, s_len));
		if (ret == 0) {
			pr_warn("HA_compare: tcp data is different\n");
			return 0;
		}
	}

#undef compare

	return ret ?:SAME_PACKET;

out:
	if (ret & BYPASS_MASTER)
		m->tcp->ack_seq = min(m->tcp->ack_seq, s->tcp->ack_seq);
	return ret;
}

static int
compare_ip_packet(struct compare_info *m, struct compare_info *s)
{
	int ret;

	if (unlikely(m->ip->ihl * 4 > m->length)) {
		pr_warn("HA_compare: master iphdr is corrupted\n");
		return 0;
	}

	if (unlikely(s->ip->ihl * 4 > s->length)) {
		pr_warn("HA_compare: slaver iphdr is corrupted\n");
		return 0;
	}

#define compare(elem)							\
	if (unlikely(m->ip->elem != s->ip->elem)) {			\
		pr_warn("HA_compare: iphdr's %s is different\n",	\
			#elem);\
		pr_warn("HA_compare: master %s: %u\n", #elem,		\
			m->ip->elem);					\
		pr_warn("HA_compare: slaver %s: %u\n", #elem,		\
			s->ip->elem);					\
		print_debuginfo(m, s);					\
		return 0;						\
	}

	compare(version);
	compare(ihl);
	compare(protocol);
	compare(saddr);
	compare(daddr);

	/* IP options */
	if (memcmp((char *)m->ip+20, (char*)s->ip+20, m->ip->ihl*4 - 20)) {
		pr_warn("HA_compare: iphdr option is different\n");
		print_debuginfo(m, s);
		return 0;
	}

	m->ip_packet = (char *)m->ip + m->ip->ihl * 4;
	if (m->length <= htons(m->ip->tot_len))
		m->length -= m->ip->ihl * 4;
	else
		m->length = htons(m->ip->tot_len) - m->ip->ihl * 4;
	s->ip_packet = (char *)s->ip + s->ip->ihl * 4;
	if (s->length <= htons(s->ip->tot_len))
		s->length -= s->ip->ihl * 4;
	else
		s->length = htons(s->ip->tot_len) - s->ip->ihl * 4;

	switch(m->ip->protocol) {
	case IPPROTO_TCP:
		ret = compare_tcp_packet(m, s);
		break;
	case IPPROTO_UDP:
		/* TODO */
	default:
//		pr_info("unknown protocol: %u", ntohs(master->protocol));
		if (m->length != s->length) {
			pr_warn("HA_compare: the length of packet is different\n");
			print_debuginfo(m, s);
			return 0;
		}
		ret = compare_other_packet(m->ip_packet, s->ip_packet, m->length);
	}
	if (!ret) {
		print_debuginfo(m, s);
		return 0;
	}

	if (ret != SAME_PACKET)
		return ret;

	compare(tos);
	compare(tot_len);
	compare(frag_off);
	compare(ttl);
	if (!ignore_id) {
		compare(id);
		compare(check);
	}

#undef compare

	last_id = htons(m->ip->id);

	return SAME_PACKET;
}

static int
compare_skb(struct compare_info *m, struct compare_info *s)
{
	int ret;

	m->eth = (struct ethhdr *)m->skb->data;
	s->eth = (struct ethhdr *)s->skb->data;
	m->length = m->skb->len;
	s->length = s->skb->len;

	if (unlikely(m->length < sizeof(struct ethhdr))) {
		pr_warn("HA_compare: master packet is corrupted\n");
		goto different;
	}

	if (unlikely(s->length < sizeof(struct ethhdr))) {
		pr_warn("HA_compare: slaver packet is corrupted\n");
		goto different;
	}

	if (m->length < 60 && s->length == 60)
		s->length = m->length;

	if (unlikely(m->eth->h_proto != s->eth->h_proto)) {
		pr_warn("HA_compare: protocol in eth header is different\n");
		pr_warn("HA_compare: master's protocol: %d\n", ntohs(m->eth->h_proto));
		pr_warn("HA_compare: slaver's protocol: %d\n", ntohs(s->eth->h_proto));
		goto different;
	}

	m->packet = (char *)m->eth + sizeof(struct ethhdr);
	s->packet = (char *)s->eth + sizeof(struct ethhdr);
	m->length -= sizeof(struct ethhdr);
	s->length -= sizeof(struct ethhdr);

	switch(ntohs(m->eth->h_proto)) {
	case ETH_P_IP:
		ret = compare_ip_packet(m, s);
		break;
	case ETH_P_ARP:
		ret = compare_arp_packet(m, s);
		if (!ret) {
			printk("HA_compare: master packet, len=%d\n", m->length);
			debug_print_arp(m->packet);
			printk("HA_compare: slaver packet, len=%d\n", s->length);
			debug_print_arp(s->packet);
		}
		break;
	default:
//		pr_debug("HA_compare: unexpected protocol: %d\n", eth_master->h_proto);
		if (m->length != s->length) {
			pr_warn("HA_compare: the length of packet is different\n");
			goto different;
		}
		ret = compare_other_packet(m->packet, s->packet, m->length);
	}
	if (!ret) {
		pr_warn("HA_compare: compare_xxx_packet() fails %04x\n", ntohs(m->eth->h_proto));
		goto different;
	}

	if (ret == SAME_PACKET) {
		same_count++;
		ret = DROP_SLAVER | BYPASS_MASTER;
	}
	return ret;

different:
	reset_compare_status();
	return 0;
}

static void clear_slaver_queue(void)
{
	int i;
	struct sk_buff *skb;
	struct hash_head *h = &slaver_queue->blo;

	spin_lock(&slaver_queue->qlock_blo);

	for (i = 0; i < HASH_NR; i++) {
		skb = __skb_dequeue(&h->e[i].queue);
		while (skb != NULL) {
			slaver_queue->sch->qstats.backlog -= qdisc_pkt_len(skb);
			kfree_skb(skb);
			skb = __skb_dequeue(&h->e[i].queue);
		}
		slaver_queue->blo.e[i].qlen = 0;
	}

	spin_unlock(&slaver_queue->qlock_blo);
}

static void move_master_queue(void)
{
	int i;
	struct sk_buff *skb;
	struct hash_head *h = &master_queue->blo;

	spin_lock(&master_queue->qlock_blo);
	spin_lock(&wqlock);

	for (i = 0; i < HASH_NR; i++) {
		skb = __skb_dequeue(&h->e[i].queue);
		while (skb != NULL) {
			__skb_queue_tail(&wait_for_release, skb);
			skb = __skb_dequeue(&h->e[i].queue);
		}
		master_queue->blo.e[i].qlen = 0;
	}

	spin_unlock(&wqlock);
	spin_unlock(&master_queue->qlock_blo);
}

static void release_queue(void)
{
	struct sk_buff *skb;
	int flag = 0;

	spin_lock(&master_queue->qlock_rel);
	spin_lock(&wqlock);

	skb = __skb_dequeue(&wait_for_release);
	while (skb != NULL) {
		flag = 1;
		++rel_count;
		__skb_queue_tail(&master_queue->rel, skb);
		skb = __skb_dequeue(&wait_for_release);
	}

	spin_unlock(&wqlock);
	spin_unlock(&master_queue->qlock_rel);
	if (flag)
		netif_schedule_queue(master_queue->sch->dev_queue);
}


void update(int qlen)
{
	struct sk_buff *skb_m;
	struct sk_buff *skb_s;
	struct sk_buff *skb;
	int flag = 0;
	unsigned long start;
	unsigned int this_loop = 0;
	int i;
	int ret;
	struct compare_info info_m, info_s;

	/*
	 *  Compare starts untill two Qdisc are created.
	 */
	if (master_queue == NULL || slaver_queue == NULL) {
		printk("HA_compare: ignore skb in checkpoint due to qdisc not ready.\n");
		return;
	}

	statis._update++;

	if (test_and_set_bit(HASTATE_RUNNING_NR, &state))
		return;

	start = jiffies;

	while (1) {
		if (test_bit(HASTATE_INCHECKPOINT_NR, &state))
			break;

		spin_lock(&master_queue->qlock_blo);
		spin_lock(&slaver_queue->qlock_blo);

		for (i = 0; i < HASH_NR; i++) {
			skb = skb_peek(&master_queue->blo.e[i].queue);
			if (skb != NULL) {
				skb = skb_peek(&slaver_queue->blo.e[i].queue);
				if (skb != NULL)
					break;
			}

		}

		if (i >= HASH_NR) {
			spin_unlock(&slaver_queue->qlock_blo);
			spin_unlock(&master_queue->qlock_blo);
			break;
		}

		if (flag == 0) {
			flag = 1;
			statis._update_eff++;
		}

		this_loop++;
		statis._loops_tot++;

		skb_m = __skb_dequeue(&master_queue->blo.e[i].queue);
		skb_s = __skb_dequeue(&slaver_queue->blo.e[i].queue);

		master_queue->blo.e[i].qlen--;
		slaver_queue->blo.e[i].qlen--;

		spin_unlock(&slaver_queue->qlock_blo);
		spin_unlock(&master_queue->qlock_blo);

		info_m.skb = skb_m;
		info_s.skb = skb_s;
		info_m.last_seq = master_queue->blo.e[i].last_seq;
		ret = compare_skb(&info_m, &info_s);
		if (ret) {
			if (ret & BYPASS_MASTER) {
				spin_lock(&master_queue->qlock_rel);
				__skb_queue_tail(&master_queue->rel, skb_m);
				spin_unlock(&master_queue->qlock_rel);
				netif_schedule_queue(master_queue->sch->dev_queue);
			} else {
				spin_lock(&master_queue->qlock_blo);
				__skb_queue_head(&master_queue->blo.e[i].queue, skb_m);
				master_queue->blo.e[i].qlen++;
				spin_unlock(&master_queue->qlock_blo);
			}

			if (ret & DROP_SLAVER) {
				spin_lock(&slaver_queue->qlock_rel);
				__skb_queue_tail(&slaver_queue->rel, skb_s);
				spin_unlock(&slaver_queue->qlock_rel);
				netif_schedule_queue(slaver_queue->sch->dev_queue);
			} else {
				spin_lock(&slaver_queue->qlock_blo);
				__skb_queue_head(&slaver_queue->blo.e[i].queue, skb_s);
				slaver_queue->blo.e[i].qlen++;
				spin_unlock(&slaver_queue->qlock_blo);
			}
			master_queue->blo.e[i].last_seq = info_m.last_seq;
			//printk("netif_schedule%u.\n", cnt);
		} else {
			/*
			 *  Put makster's skb to temporary queue, drop slaver's.
			 */
			spin_lock(&wqlock);
			__skb_queue_tail(&wait_for_release, skb_m);
			spin_unlock(&wqlock);

			slaver_queue->sch->qstats.backlog -= qdisc_pkt_len(skb_s);
			kfree_skb(skb_s);

			/* Trigger a checkpoint, if pending bit is allready set, just ignore. */
			if ( !test_and_set_bit(HASTATE_PENDING_NR, &state) ) {
				set_bit(HASTATE_INCHECKPOINT_NR, &state);
				wake_up_interruptible(&queue);
			}
			break;
		}

	}
	statis._loops_last = this_loop;
	clear_bit(HASTATE_RUNNING_NR, &state);
}

int read_proc(char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	struct sk_buff *skb;
	int i;

	if (statis._update_eff == 0)
		statis._update_eff = 1;
	printk("STAT: update=%u, update_m=%u, update_s=%u, update_eff=%u, loops_tot=%u, loops_avg=%u, loops_last=%u.\n",
		statis._update, statis._update_m, statis._update_s, statis._update_eff, statis._loops_tot,
		statis._loops_tot/statis._update_eff, statis._loops_last);
	printk("STAT Debug info:\n");
	printk("\nSTAT: status=%lx.\n", state);

	spin_lock(&master_queue->qlock_blo);
	for (i = 0; i < HASH_NR; i++) {
		skb = skb_peek(&master_queue->blo.e[i].queue);
		if (skb != NULL)
			printk("STAT: m_blo[%d] not empty.\n", i);
	}
	spin_unlock(&master_queue->qlock_blo);

	spin_lock(&master_queue->qlock_rel);
	skb = skb_peek(&master_queue->rel);
	if (skb != NULL)
		printk("STAT: m_rel not empty.\n");
	spin_unlock(&master_queue->qlock_rel);

	spin_lock(&slaver_queue->qlock_blo);
	for (i = 0; i < HASH_NR; i++) {
		skb = skb_peek(&slaver_queue->blo.e[i].queue);
		if (skb != NULL)
			printk("STAT: s_blo[%d] not empty.\n", i);
	}
	spin_unlock(&slaver_queue->qlock_blo);

	spin_lock(&slaver_queue->qlock_rel);
	skb = skb_peek(&slaver_queue->rel);
	if (skb != NULL)
		printk("STAT: s_rel not empty.\n");
	spin_unlock(&slaver_queue->qlock_rel);

	return 0;
}

int write_proc(struct file *file, const char *buffer, unsigned long count, void *data)
{
	char buf[20];
	int ret;

	ret = copy_from_user(buf, buffer, count);
	if (ret < 0)
		return 0;
	if (buf[0]=='f') { //failover manually
		fail = 1;
		test_and_set_bit(HASTATE_PENDING_NR, &state);
		wake_up_interruptible(&queue);
		printk("failover.\n");
	} else if (buf[0]=='r')
		fail = 0;

	return count;
}

static int __init compare_module_init(void)
{
	int result;
	dev_t dev;

	/* allocate a device id */
	result = alloc_chrdev_region(&dev, cmp_minor, 1, "HA_compare");
	if (result < 0) {
		printk(KERN_WARNING "HA_compare: can't get device id.\n");
		return result;
	}
	cmp_major = MAJOR(dev);

	/* setup device */
	result = cmp_setup_cdev(&cmp_dev);
	if (result) {
		printk(KERN_WARNING "HA_compare: can't setup device.\n");
		unregister_chrdev_region(MKDEV(cmp_major, cmp_minor), 1);
		return result;
	}

	sema_init(&cmp_dev.sem, 1);
	init_waitqueue_head(&queue);

	s_compare_update = update;
	m_compare_update = update;
	skb_queue_head_init(&wait_for_release);
	spin_lock_init(&wqlock);

	memset(&statis, 0, sizeof(struct statistic_data));
	proc_entry = create_proc_entry("HA_compare", 0, NULL);
	proc_entry->read_proc = read_proc;
	proc_entry->write_proc = write_proc;

	return 0;
}

static void __exit compare_module_exit(void)
{
	/* del device */
	cdev_del(& cmp_dev.cdev);

	/* free a device id */
	unregister_chrdev_region(MKDEV(cmp_major, cmp_minor), 1);

	s_compare_update = NULL;
	m_compare_update = NULL;

	remove_proc_entry("HA_compare", NULL);
}
module_init(compare_module_init);
module_exit(compare_module_exit);
MODULE_LICENSE("GPL");

