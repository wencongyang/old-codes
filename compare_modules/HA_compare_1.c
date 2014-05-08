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
#include "hash.h"

typedef void (*PTRFUN)(int id);
int cmp_open(struct inode*, struct file*);
int cmp_release(struct inode*, struct file*);
int cmp_ioctl(struct file*, unsigned int, unsigned long);
unsigned short last_id = 0;
int fail = 0;

#define COMP_IOC_MAGIC 		'k'
#define COMP_IOCTWAIT 		_IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTSUSPEND 	_IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME 	_IO(COMP_IOC_MAGIC, 2)
#define COMP_IOCT_SWITCH	_IO(COMP_IOC_MAGIC, 3)

enum colo_mode {
	COMPARE_MODE,
	BUFFER_MODE,
} curr_mode;

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
	unsigned int debugf[10];
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

struct timestampe {
	unsigned long long arrive;
	unsigned short dst;
};

extern struct timestampe tsm_list[100];
extern struct timestampe tss_list[100];
extern int tsm_len;
extern int tss_len;

extern struct sched_data *master_queue;
extern struct sched_data *slaver_queue;
extern PTRFUN s_compare_update;
extern PTRFUN m_compare_update;
static void clear_slaver_queue();
static void clear_master_queue();
static void move_master_queue();
static void release_queue();
void update(int id);

wait_queue_head_t queue;
int cmp_major=0, cmp_minor=0;
//int pending=0; /* a new checkponit need*/
//int in_checkpoint=0; /* whether a checkpoint is running */
#define HASTATE_PENDING_NR	0
#define HASTATE_INCHECKPOINT_NR	1
#define HASTATE_RUNNING_NR	2
#define HASTATE_PENDING 	(1U << HASTATE_PENDING_NR)
#define HASTATE_INCHECKPOINT	(1U << HASTATE_INCHECKPOINT_NR)
#define HASTATE_RUNNING		(1U << HASTATE_RUNNING_NR)

//unsigned int state = HASTATE_INCHECKPOINT;
unsigned int state = 0;
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

#ifdef CHECK_QUEUE
static int check_queue(void)
{
	struct hash_head *master = &master_queue->blo;
	struct hash_head *slaver = &slaver_queue->blo;
	int i, m_qlen, s_qlen;
	uint32_t now = jiffies;

	for (i = 0; i < HASH_NR; i++) {
		m_qlen = master->e[i].qlen;
		s_qlen = slaver->e[i].qlen;
		if (m_qlen > 0 && s_qlen > 0)
			continue;
		if (m_qlen == 0 && s_qlen ==0)
			continue;

		if (m_qlen == 0)
			if (now - slaver->e[i].last_jiffies > 500)
				goto checkpoint;
		else if (s_qlen == 0)
			if (now - master->e[i].last_jiffies > 500)
				goto checkpoint;
	}

	return 0;

checkpoint:
	printk("[NOTICE]Force a checkpoint.\n");
	set_bit(HASTATE_INCHECKPOINT_NR, &state);
	return 1;
}
#endif

int rel_count = 0;
int cmp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	//struct _cmp_dev *dev;
	int ret;
	int new_mode;
	unsigned long jiffies;

	//printk("HA_compare: ioctl, cmd=%d, arg=%lx.\n", cmd, arg);
	//dev = container_of(inode->i_cdev, struct _cmp_dev, cdev);	

	switch(cmd) {
	case COMP_IOCTWAIT:
		clear_bit(HASTATE_INCHECKPOINT_NR, &state);
		//state &= ~HASTATE_INCHECKPOINT; // compare process will begin
		/* wait for a new checkpoint */
		if (fail) {
			set_bit(HASTATE_INCHECKPOINT_NR, &state);
			//state |= HASTATE_INCHECKPOINT;
			return -1;
		}
#if 1
		jiffies = msecs_to_jiffies(arg);
		ret = wait_event_interruptible_timeout(queue, state&HASTATE_PENDING, jiffies);
		if (ret == 0) {
#ifdef CHECK_QUEUE
			/* Timeout */
			if (check_queue())
				/* return 0 will trigger a new checkpoint */
				return 0;
#endif
			return -ETIME;
		}

		if (ret < 0)
			return -ERESTART;
#else
		if (wait_event_interruptible(queue, state & HASTATE_PENDING))
			return -ERESTARTSYS;
#endif

		/*
		 *  A new checkpoint starts, block input packets to VMs. 
		 */
		//state &= ~HASTATE_PENDING;
		clear_bit(HASTATE_PENDING_NR, &state);	

		if (fail) {
			set_bit(HASTATE_INCHECKPOINT_NR, &state);
			//state |= HASTATE_INCHECKPOINT;
			return -1;
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
		//clear_master_queue();
		clear_slaver_queue();
		break;
	case COMP_IOCTRESUME:
		/*
		 *  Checkpoint finish, relese skb in temporary queue 
		 */
		printk(KERN_NOTICE "HA_compare: --------checkpoint finish.\n");
		release_queue();
		//printk("HA_compare: %d pkts release in checkpoint.\n", rel_count);	
		rel_count = 0;	
	
		//state &= ~HASTATE_INCHECKPOINT; // compare process will begin
		//update(); // VMs are running at this point, trigger a comparision in case
			  // there are allready packets in queues.
		break;
	case COMP_IOCT_SWITCH:
		new_mode = arg;
		switch(new_mode) {
		default:
			return -EINVAL;
		case COMPARE_MODE:
		case BUFFER_MODE:
			curr_mode = new_mode;
			pr_info("HA_compare: switch to %s mode\n",
				new_mode == COMPARE_MODE ? "compare" : "buffer");
		}
		break;
	}

	return 0;	
}

static void debug_print_ip(const unsigned char* p)
{
	unsigned char *t;
	unsigned short len;
	unsigned short id;

	t = &len;
	*(t+1) = *((unsigned char *)(p + 2));
	*t = *((unsigned char *)(p + 3));

	t = &id;
	*(t+1) = *((unsigned char *)(p + 4));
	*t = *((unsigned char *)(p + 5));

	printk("HA_compare:[IP]len = %u, id= %u.\n", len, id);
}

static void debug_print(const unsigned char* p)
{
	int i;
	unsigned char n[50], *t;
	unsigned short id;
	unsigned short src_port;
	unsigned short dst_port;
	unsigned int ack, seq;
	unsigned char protocol;
	unsigned int XID;
	unsigned int stamp;
	unsigned short len;
	unsigned short wnd_size;

	t = &protocol;
	*t = *((unsigned char *)(p + 23));

	t = &len;
	*(t+1) = *((unsigned char *)(p+16));
	*t = *((unsigned char *)(p+17));

	printk("HA_compare:len = %d.\n", len);

	if (protocol == 17) {// UDP
		t = &src_port;
		*(t+1) = *((unsigned char *)(p + 34));
		*t = *((unsigned char *)(p + 35));
		
		t = &dst_port;
		*(t+1) = *((unsigned char *)(p + 36));
		*t = *((unsigned char *)(p + 37));
		
		t = &XID;
		*(t+3) = *((unsigned char *)(p + 42));
		*(t+2) = *((unsigned char *)(p + 43));
		*(t+1) = *((unsigned char *)(p + 44));
		*t = *((unsigned char *)(p + 45));

		t = &stamp;
		*(t+3) = *((unsigned char *)(p + 74));
		*(t+2) = *((unsigned char *)(p + 75));
		*(t+1) = *((unsigned char *)(p + 76));
		*t = *((unsigned char *)(p + 77));

		printk("HA_compare:[UDP] src=%u, dst=%u, XID=%u, stamp=%u\n", 
			src_port, dst_port, XID, stamp);	

		return;	
	} else if (protocol == 6) {// TCP

		t = &id;
		*(t+1) = *((unsigned char *)(p + 18));
		*t = *((unsigned char *)(p + 19));

		t = &src_port;
		*(t+1) = *((unsigned char *)(p + 34));
		*t = *((unsigned char *)(p + 35));

		t = &dst_port;
		*(t+1) = *((unsigned char *)(p + 36));
		*t = *((unsigned char *)(p + 37));

		t = &seq;
		*(t+3) = *((unsigned char *)(p + 38));
		*(t+2) = *((unsigned char *)(p + 39));
		*(t+1) = *((unsigned char *)(p + 40));
		*t = *((unsigned char *)(p + 41));
		
		t = &ack;
		*(t+3) = *((unsigned char *)(p + 42));
		*(t+2) = *((unsigned char *)(p + 43));
		*(t+1) = *((unsigned char *)(p + 44));
		*t = *((unsigned char *)(p + 45));

		debug_print_ip(p+14);
		printk(KERN_DEBUG "HA_compare:[TCP] src=%u, dst=%u, seq = %u, ack=%u\n", 
					src_port, dst_port, seq, ack);
                t = &wnd_size;
		*(t+1) = *((unsigned char *)(p + 48));
		*t = *((unsigned char *)(p + 49));
		printk(KERN_DEBUG "HA_compare:[TCP] window size %d.\n",wnd_size);

		for (i = 34; i < 34+32; i++)
			n[i-34] = *((unsigned char *)(p + i));
		printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n", 
			n[0], n[1], n[2], n[3], n[4], n[5], n[6], n[7]);
		printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
			n[8], n[9], n[10], n[11], n[12], n[13], n[14], n[15]); 
		printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
			n[16], n[17], n[18], n[19], n[20], n[21], n[22], n[23]);
		printk(KERN_DEBUG "HA_compare: %02x %02x %02x %02x\t%02x %02x %02x %02x\n",
			n[24], n[25], n[26], n[27], n[28], n[29], n[30], n[31]);

	
		/*if (p->len-54 >= 6) {
			for (i = 54; i < 54+6; i++)
				n[i-34] = *((unsigned char *)(p->data + i));
			printk(KERN_DEBUG "%02x %02x %02x %02x\t%02x %02x\n",
			n[20], n[21], n[22], n[23], n[24], n[25]);
		}*/
	}
	else
		printk("HA_compare: unkown protocol: %u\n", protocol);
}
static void get_udp_info(const unsigned char* p, unsigned char *protocol, 
			unsigned int *XID, unsigned int *stamp, 
			unsigned short *src_port, unsigned short *dst_port)
{
	unsigned char *t;

	t = protocol;
	*t = *((unsigned char *)(p + 23));

	if (*protocol == 17) {// UDP
		t = src_port;
		*(t+1) = *((unsigned char *)(p + 34));
		*t = *((unsigned char *)(p + 35));
		
		t = dst_port;
		*(t+1) = *((unsigned char *)(p + 36));
		*t = *((unsigned char *)(p + 37));
		
		t = XID;
		*(t+3) = *((unsigned char *)(p + 42));
		*(t+2) = *((unsigned char *)(p + 43));
		*(t+1) = *((unsigned char *)(p + 44));
		*t = *((unsigned char *)(p + 45));

		t = stamp;
		*(t+3) = *((unsigned char *)(p + 74));
		*(t+2) = *((unsigned char *)(p + 75));
		*(t+1) = *((unsigned char *)(p + 76));
		*t = *((unsigned char *)(p + 77));
	}
}

static int is_nfs_pkt(const struct sk_buff *p)
{
	unsigned char *buf, protocol;
	unsigned short src_port, dst_port;
	unsigned short XID, stamp;
	
	buf = p->data;
	get_udp_info(buf, &protocol, &XID, &stamp, &src_port, &dst_port);
	
	return protocol == 17;
}

static int same(const struct sk_buff *p, const struct sk_buff *q)
{
	int idx, lenp, lenq, len;
	unsigned char *cp1, *cp2, *t;
	unsigned char *bufp, *bufq;
	unsigned char p_protocol, q_protocol;
	unsigned short p_src_port, p_dst_port;
	unsigned short q_src_port, q_dst_port;
	unsigned int p_XID, p_stamp;
	unsigned int q_XID, q_stamp;

	lenp = p->len;
	lenq = q->len;

	/*Only compare the eth header, ip header, tcp header firstly*/
	lenp = (lenp > 50 ? 50 : lenp);
	lenq = (lenq > 50 ? 50 : lenq);

	//skb_header_pointer(p, 0, lenp, bufp);
	//skb_header_pointer(q, 0, lenq, bufq);
	bufp = p->data;
	bufq = q->data;

	//return 1;

	/*if (lenp != lenq) {
		printk(KERN_DEBUG "HA_compare: Length: %d, %d\n", lenp, lenq);
		printk(KERN_DEBUG "HA_compare: Master pkt:\n");
		debug_print(bufp);
		printk(KERN_DEBUG "HA_compare: Slaver pkt:\n");
		debug_print(bufq);
		
		return 0;
	}*/

	len = lenp < lenq ? lenp : lenq;

	/*get_udp_info(bufp, &p_protocol, &p_XID, &p_stamp, &p_src_port, &p_src_port);
	get_udp_info(bufq, &q_protocol, &q_XID, &q_stamp, &q_src_port, &q_src_port);

	if ( p_protocol == 17 && q_protocol == 17 ) {
		// Two nfs UDP pkts. Ignore the stamp field.
		if (p_XID == q_XID && p_src_port == q_src_port
			&& p_dst_port == q_dst_port) {
			//printk("HA_compare: The same, %u\n", jiffies);
			return 1;
		}else {
			printk(KERN_DEBUG "HA_compare: Master pkt:\n");
			debug_print(bufp);
			printk(KERN_DEBUG "HA_compare: Slaver pkt:\n");
			debug_print(bufq);
			return 0;
		}
	}*/	

	for (idx = 0; idx < len; idx++) {
		if ( idx == 50 || idx == 51)
			continue;
		cp1 = (unsigned char*)(bufp + idx);
		cp2 = (unsigned char*)(bufq + idx);
		if (*cp1 != *cp2) {
#if 1
			printk("HA_compare: same=%u, last id=%u\n", same_count, last_id);
			same_count = 0;
			printk(KERN_DEBUG "HA_compare: diff at pos %d\n", idx);
			printk(KERN_DEBUG "HA_compare: Master pkt:\n");
			debug_print(bufp);
			printk(KERN_DEBUG "HA_compare: Slaver pkt:\n");
			debug_print(bufq);
			return 0;
#else
			return 1;
#endif
		}
	}
	
	t = &last_id;
	*(t+1) = *((unsigned char *)(bufp + 18));
	*t = *((unsigned char *)(bufp + 19));

	//printk(KERN_DEBUG "HA_compare: The same, %u\n", jiffies);
	same_count++;
	return 1;
}

static void clear_slaver_queue()
{
	int i, b;
	struct sk_buff *skb;
	struct hash_head *h = &slaver_queue->blo;
	
	spin_lock(&slaver_queue->qlock_blo);
	
	for (i = 0; i < HASH_NR; i++) {
		//b = h->e[i].dst;
		//if (b >= 0) {
			skb = __skb_dequeue(&h->e[i].queue);
			while (skb != NULL) {
				slaver_queue->sch->qstats.backlog -= qdisc_pkt_len(skb);
				kfree_skb(skb);
				skb = __skb_dequeue(&h->e[i].queue);
			}
			slaver_queue->blo.e[i].qlen = 0; 
			//h->e[i].dst = -1;
			//h->map[b] = -1;
		//}
	}

	spin_unlock(&slaver_queue->qlock_blo);
}

static void clear_master_queue()
{
	int i, b;
	struct sk_buff *skb;
	struct hash_head *h = &master_queue->blo;
	
	spin_lock(&master_queue->qlock_blo);

	for (i = 0; i < HASH_NR; i++) {
		//b = h->e[i].dst;
		//if (b >= 0) {
			skb = __skb_dequeue(&h->e[i].queue);
			while (skb != NULL) {
				master_queue->sch->qstats.backlog -= qdisc_pkt_len(skb);
				kfree_skb(skb);
				skb = __skb_dequeue(&h->e[i].queue);
			} 
			master_queue->blo.e[i].qlen = 0;
			//h->e[i].dst = -1;
			//h->map[b] = -1;
		//}
	}

	spin_unlock(&master_queue->qlock_blo);
}

static void move_master_queue()
{
	int i, b;
	struct sk_buff *skb;
	struct hash_head *h = &master_queue->blo;

	spin_lock(&master_queue->qlock_blo);
	spin_lock(&wqlock);
	
	for (i = 0; i < HASH_NR; i++) {
		//b = h->e[i].dst;
		//if (b >= 0) {
			skb = __skb_dequeue(&h->e[i].queue);
			while (skb != NULL) {
				__skb_queue_tail(&wait_for_release, skb);
				skb = __skb_dequeue(&h->e[i].queue);
			} 
			master_queue->blo.e[i].qlen = 0;
			//h->e[i].dst = -1;
			//h->map[b] = -1;
		//}
	}

	spin_unlock(&wqlock);
	spin_unlock(&master_queue->qlock_blo);
}

static void release_queue()
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
	static int master_count = 0;
	static int slaver_count = 0;
	int flag = 0;
	static unsigned int cnt = 0;
	unsigned long start;
	unsigned int this_loop = 0;
	int i, j, ib, jb;
	unsigned int value;
	int rc;
	/*
	 *  Compare starts untill two Qdisc are created.
	 */
	//if (id == 0)
	//	printk("HA_compare: master skb %d.\n", ++master_count);
	//else if (id == 1)
	//	printk("HA_compare: slaver skb %d.\n", ++slaver_count);
	if (master_queue == NULL || slaver_queue == NULL) {
		printk("HA_compare: ignore skb in checkpoint due to qdisc not ready.\n");
		return;
	}

	statis._update++;
		

	if ( test_and_set_bit(HASTATE_RUNNING_NR, &state) )
		return;
	
	statis.debugf[0]++;

	/*Buffered too much.*/
	/*if ( !(state & HASTATE_INCHECKPOINT) && qlen > MAXQ) {
		printk("extend the max queue, len=%d\n", qlen);
		goto ck;
	}*/
	
	start = jiffies;

	while (1) {

		/*if ( jiffies > start + 5) {
			printk("WARINING: too much time.\n");
			//break;
		}*/

		if ( test_bit(HASTATE_INCHECKPOINT_NR, &state) ) {
			//if (id != -1)
			//	printk("HA_compare: ignore skb in checkpoint.\n");
			break;;
		}
		statis.debugf[1]++;

		spin_lock(&master_queue->qlock_blo);
		spin_lock(&slaver_queue->qlock_blo);

		for (i = 0; i < HASH_NR; i++) {
			//ib = master_queue->blo.e[i].dst;
			skb = skb_peek(&master_queue->blo.e[i].queue);
			if (skb != NULL) {
				//j = slaver_queue->blo.map[ib];
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

		statis.debugf[1]++;
		
		if (flag == 0) {
			flag = 1;
			statis._update_eff++;
		}

		this_loop++;
		statis._loops_tot++;
	
		/*if ( master_queue->blo.e[i].dst != slaver_queue->blo.e[j].dst ) {
			printk("ERROR: dst is diff.\n");
			spin_unlock(&slaver_queue->qlock_blo);
			spin_unlock(&master_queue->qlock_blo);
		}*/
	
		skb_m = __skb_dequeue(&master_queue->blo.e[i].queue);
		skb_s = __skb_dequeue(&slaver_queue->blo.e[i].queue);

		master_queue->blo.e[i].qlen--;
		slaver_queue->blo.e[i].qlen--;

		/*skb = skb_peek(&master_queue->blo.e[i].queue);
		if (skb == NULL) {
			master_queue->blo.e[i].dst = -1;
			master_queue->blo.map[ib] = -1;
		}

		skb = skb_peek(&slaver_queue->blo.e[j].queue);
		if (skb == NULL) {
			slaver_queue->blo.e[j].dst = -1;
			slaver_queue->blo.map[ib] = -1;
		}*/

		spin_unlock(&slaver_queue->qlock_blo);
		spin_unlock(&master_queue->qlock_blo);

		rc = same(skb_m, skb_s);

		if (rc && (curr_mode == COMPARE_MODE)) {
			/*
			 *  Packets are the same, put skb_m to master_queue->rel for releasing,
			 *  and also put skb_s to slaver_queue->rel, it will be freed by enqueue
			 *  routine of sch_slaver.
			 */	
			spin_lock(&master_queue->qlock_rel);
			spin_lock(&slaver_queue->qlock_rel);
			
			__skb_queue_tail(&master_queue->rel, skb_m);
			//spin_unlock(&master_queue->qlock_rel);
			
			__skb_queue_tail(&slaver_queue->rel, skb_s);
			//slaver_queue->sch->qstats.backlog -= qdisc_pkt_len(skb_s);
			//kfree(skb_s);
		
			spin_unlock(&master_queue->qlock_rel);
			spin_unlock(&slaver_queue->qlock_rel);
			
			
			netif_schedule_queue(master_queue->sch->dev_queue);
			netif_schedule_queue(slaver_queue->sch->dev_queue);
			//printk("netif_schedule%u.\n", cnt);	
		} else if (rc) {
			/* buffer mode */
			spin_lock(&wqlock);
			__skb_queue_tail(&wait_for_release, skb_m);
			spin_unlock(&wqlock);

			slaver_queue->sch->qstats.backlog -= qdisc_pkt_len(skb_s);
			kfree_skb(skb_s);
		} else {
			/*
			 *  Put makster's skb to temporary queue, drop slaver's.
			 */
			
			//netif_schedule_queue(master_queue->sch->dev_queue);
			//netif_schedule_queue(slaver_queue->sch->dev_queue);
			
			spin_lock(&wqlock);
			__skb_queue_tail(&wait_for_release, skb_m);
			spin_unlock(&wqlock);

			slaver_queue->sch->qstats.backlog -= qdisc_pkt_len(skb_s);
			kfree_skb(skb_s);

ck:			/* Trigger a checkpoint, if pending bit is allready set, just ignore. */
			if ( !test_and_set_bit(HASTATE_PENDING_NR, &state) ) {
				set_bit(HASTATE_INCHECKPOINT_NR, &state);
				wake_up_interruptible(&queue);
			}
		}

	}
	//netif_schedule_queue(master_queue->sch->dev_queue);
	//netif_schedule_queue(slaver_queue->sch->dev_queue);
	statis._loops_last = this_loop;
	clear_bit(HASTATE_RUNNING_NR, &state);
	//update(-1);
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
	for (i = 0; i < 10; i++)
		printk(" %lx", statis.debugf[i]);
	printk("\nSTAT: status=%lx.\n", state);
	
	
	spin_lock(&master_queue->qlock_blo);	
	skb = skb_peek(&master_queue->blo);
	if (skb != NULL)
		printk("STAT: m_blo not empty.\n");
	spin_unlock(&master_queue->qlock_blo);
	
	spin_lock(&master_queue->qlock_rel);	
	skb = skb_peek(&master_queue->rel);
	if (skb != NULL)
		printk("STAT: m_rel not empty.\n");
	spin_unlock(&master_queue->qlock_rel);
	
	spin_lock(&slaver_queue->qlock_blo);	
	skb = skb_peek(&slaver_queue->blo);
	if (skb != NULL)
		printk("STAT: s_blo not empty.\n");
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
	int i;
	/*memset(&statis, 0, sizeof(struct statistic_data));
	netif_schedule_queue(master_queue->sch->dev_queue);*/

	copy_from_user(buf, buffer, count);
	if (buf[0]=='f') { //failover manually
		fail = 1;
		test_and_set_bit(HASTATE_PENDING_NR, &state);
		wake_up_interruptible(&queue);
		printk("failover.\n");
	} else if (buf[0]=='r')
		fail = 0;
	else if (buf[0] == 't') {
		printk("Arrive timestampe for Master:\n");
		for (i = 0; i < tsm_len; i++) {
			printk("(t:%lld, dst:%d. )", tsm_list[i].arrive, tsm_list[i].dst);
			if (i && (i % 5 == 0))
				printk("\n");
		}
		printk("Arrive timestampe for Slaver:\n");
		for (i = 0; i < tss_len; i++) {
			printk("(t:%lld, dst:%d. )", tss_list[i].arrive, tss_list[i].dst);
			if (i && (i % 5 == 0))
				printk("\n");
		}
		tsm_len = tss_len = 0;
	}

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
	
	//init_MUTEX(&cmp_dev.sem);
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

