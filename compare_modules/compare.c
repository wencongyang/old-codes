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
#include <linux/if_arp.h>
#include <linux/kthread.h>

#include "comm.h"
#include "compare.h"

bool ignore_id = 1;
module_param(ignore_id, bool, 0644);
MODULE_PARM_DESC(ignore_id, "bypass id difference");

bool ignore_ack_packet = 1;
module_param(ignore_ack_packet, bool, 0644);
MODULE_PARM_DESC(ignore_ack_packet, "bypass ack only packet");

bool ignore_retransmitted_packet = 1;
module_param(ignore_retransmitted_packet, bool, 0644);
MODULE_PARM_DESC(ignore_retransmitted_packet, "bypass retransmitted packets");

bool compare_tcp_data = 0;
module_param(compare_tcp_data, bool, 0644);
MODULE_PARM_DESC(compare_tcp_data, "compare tcp data");

bool ignore_tcp_window = 0;
module_param(ignore_tcp_window, bool, 0644);
MODULE_PARM_DESC(ignore_tcp_window, "ignore tcp window");

bool ignore_ack_difference = 0;
module_param(ignore_ack_difference, bool, 0644);
MODULE_PARM_DESC(ignore_ack_difference, "ignore ack difference");

int cmp_open(struct inode*, struct file*);
int cmp_release(struct inode*, struct file*);
long cmp_ioctl(struct file*, unsigned int, unsigned long);
unsigned short last_id = 0;
static int failover = 0;

struct task_struct *compare_task;

#define COMP_IOC_MAGIC 		'k'
#define COMP_IOCTWAIT 		_IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTSUSPEND 	_IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME 	_IO(COMP_IOC_MAGIC, 2)

struct proc_dir_entry* proc_entry;
struct statistic_data {
	unsigned int update;   	// call counts of update()
	unsigned int in_soft_irq;
	unsigned long long total_time;
	unsigned long long last_time;
	unsigned long long max_time;
} statis;

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

static void clear_slaver_queue(struct hash_head *h);
static void move_master_queue(struct hash_head *h);
static void release_queue(struct hash_head *h);
void update(struct hash_value *h);

wait_queue_head_t queue;
int cmp_major=0, cmp_minor=0;

enum {
	state_comparing,
	state_incheckpoint,
	state_failover,
};

static int state = state_comparing;
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
		/* wait for a new checkpoint */
#if 1
		ret = wait_event_interruptible_timeout(queue, state != state_comparing, 10);
		if (ret == 0)
			return -ETIME;

		if (ret < 0)
			return -ERESTART;
#else
		if (wait_event_interruptible(queue, state != state_comparing))
			return -ERESTART;
#endif

		if (state == state_failover)
			return -2;

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

		move_master_queue(colo_hash_head);
		clear_slaver_queue(colo_hash_head);
		break;
	case COMP_IOCTRESUME:
		/*
		 *  Checkpoint finish, relese skb in temporary queue
		 */
		printk(KERN_NOTICE "HA_compare: --------checkpoint finish.\n");
		release_queue(colo_hash_head);
		state = state_comparing;
		rel_count = 0;

		break;
	}

	return 0;
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

	pr_debug("HA_compare:[ARP] ar_hrd=%u, ar_pro=%u\n",
		htons(arp->ar_hrd), htons(arp->ar_pro));
	pr_debug("HA_compare:[ARP] ar_hln=%u, ar_pln=%u, ar_op=%u\n",
		arp->ar_hln, arp->ar_pln, htons(arp->ar_op));
	if (htons(arp->ar_op) == ARPOP_REPLY || htons(arp->ar_op) == ARPOP_REQUEST) {
		temp = (struct arp_reply *)((char*)arp + sizeof(struct arphdr));
		pr_debug("HA_compare:[ARP] ar_sha: %pM, ar_sip: %pI4\n", temp->ar_sha, temp->ar_sip);
		pr_debug("HA_compare:[ARP] ar_tha: %pM, ar_tip: %pI4\n", temp->ar_tha, temp->ar_tip);
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

int compare_other_packet(void *m, void *s, int length)
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
			pr_debug("HA_compare: master packet, len=%d\n", m->length);
			debug_print_arp(m->packet);
			pr_debug("HA_compare: slaver packet, len=%d\n", s->length);
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

static void clear_slaver_queue(struct hash_head *h)
{
	int i;
	struct sk_buff *skb;
	struct hash_value *value;

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry(value, &h->entry[i], list) {
			skb = skb_dequeue(&value->slaver_queue);
			while (skb != NULL) {
				skb_queue_tail(&value->head->slaver_data->rel, skb);
				skb = skb_dequeue(&value->slaver_queue);
			}
		}
	}
}

static void update_compare_info(struct hash_value *value, struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct iphdr *ip;

	if (htons(eth->h_proto) != ETH_P_IP)
		return;

	ip = (struct iphdr *)(skb->data + sizeof(*eth));
	ip_update_compare_info(&value->m_info, ip);
}

static void move_master_queue(struct hash_head *h)
{
	int i;
	struct sk_buff *skb;
	struct hash_value *value;

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry(value, &h->entry[i], list) {
			skb = skb_dequeue(&value->master_queue);
			while (skb != NULL) {
				update_compare_info(value, skb);
				skb_queue_tail(&h->wait_for_release, skb);
				skb = skb_dequeue(&value->master_queue);
			}
		}
	}
}

static void release_queue(struct hash_head *h)
{
	struct sk_buff *skb;
	int flag = 0;

	skb = skb_dequeue(&h->wait_for_release);
	while (skb != NULL) {
		flag = 1;
		++rel_count;
		skb_queue_tail(&h->master_data->rel, skb);
		skb = skb_dequeue(&h->wait_for_release);
	}

	if (flag)
		netif_schedule_queue(h->master_data->sch->dev_queue);
}


static void compare(struct hash_value *hash_value)
{
	struct sk_buff *skb_m;
	struct sk_buff *skb_s;
	struct sk_buff *skb;
	int ret;
	struct compare_info info_m, info_s;
	struct timespec start, end, delta;
	struct hash_head *h = hash_value->head;

	getnstimeofday(&start);
	statis.update++;

	if (in_softirq())
		statis.in_soft_irq++;

	while (1) {
		if (state != state_comparing)
			break;

		skb = skb_peek(&hash_value->master_queue);
		if (!skb)
			break;
		skb = skb_peek(&hash_value->slaver_queue);
		if (!skb)
			break;

		skb_m = skb_dequeue(&hash_value->master_queue);
		skb_s = skb_dequeue(&hash_value->slaver_queue);

		info_m.skb = skb_m;
		info_s.skb = skb_s;
		info_m.private_data = &hash_value->m_info;
		info_m.private_data = &hash_value->s_info;
		ret = compare_skb(&info_m, &info_s);
		if (ret) {
			if (likely(ret & BYPASS_MASTER)) {
				skb_queue_tail(&h->master_data->rel, skb_m);
				netif_schedule_queue(h->master_data->sch->dev_queue);
			} else {
				skb_queue_head(&hash_value->master_queue, skb_m);
			}

			if (likely(ret & DROP_SLAVER)) {
				skb_queue_tail(&h->slaver_data->rel, skb_s);
				netif_schedule_queue(h->slaver_data->sch->dev_queue);
			} else {
				skb_queue_head(&hash_value->slaver_queue, skb_s);
			}
			//printk("netif_schedule%u.\n", cnt);
		} else {
			/*
			 *  Put makster's skb to temporary queue, drop slaver's.
			 */
			skb_queue_tail(&h->wait_for_release, skb_m);

			skb_queue_tail(&h->slaver_data->rel, skb_s);

			state = state_incheckpoint;
			wake_up_interruptible(&queue);
			break;
		}

	}

	getnstimeofday(&end);
	delta = timespec_sub(end, start);
	statis.last_time = delta.tv_sec * 1000000000 + delta.tv_nsec;
	if (statis.last_time > statis.max_time)
		statis.max_time = statis.last_time;
	statis.total_time += statis.last_time;
}

static struct hash_value *get_hash_value(void)
{
	struct hash_value *value = NULL;

	spin_lock_bh(&compare_lock);
	if (list_empty(&compare_head))
		goto out;

	value = list_first_entry(&compare_head, struct hash_value,
				 compare_list);
	list_del_init(&value->compare_list);
out:
	spin_unlock_bh(&compare_lock);
	return value;
}

static int compare_kthread(void *data)
{
	struct hash_value *value;

	while(!kthread_should_stop()) {
		wait_event_interruptible(compare_queue,
					 !list_empty(&compare_head) ||
					 kthread_should_stop());

		if (kthread_should_stop())
			break;

		while(!list_empty(&compare_head)) {
			value = get_hash_value();
			if (value)
				compare(value);

			if (kthread_should_stop())
				break;
		}
	}

	return 0;
}

int read_proc(char *buf, char **start, off_t offset, int count, int *eof, void *data)
{
	struct sk_buff *skb;
	int i, j;
	struct sched_data *master_queue = colo_hash_head->master_data;
	struct sched_data *slaver_queue = colo_hash_head->slaver_data;
	struct hash_value *value;

	pr_info("STAT: update=%u, in_soft_irq=%u, total_time=%llu, last_time=%llu, max_time=%llu\n",
		statis.update, statis.in_soft_irq, statis.total_time, statis.last_time, statis.max_time);
	pr_info("STAT Debug info:\n");
	pr_info("\nSTAT: status=%d.\n", state);

	for (i = 0; i < HASH_NR; i++) {
		j = 0;
		list_for_each_entry(value, &master_queue->blo->entry[i], list) {
			skb = skb_peek(&value->master_queue);
			if (skb != NULL)
				pr_info("STAT: m_blo[%d, %d] not empty.\n", i, j);
			j++;
		}
	}

	skb = skb_peek(&master_queue->rel);
	if (skb != NULL)
		pr_info("STAT: m_rel not empty.\n");

	for (i = 0; i < HASH_NR; i++) {
		j = 0;
		list_for_each_entry(value, &slaver_queue->blo->entry[i], list) {
			skb = skb_peek(&value->slaver_queue);
			if (skb != NULL)
				pr_info("STAT: s_blo[%d] not empty.\n", i);
			j++;
		}
	}

	skb = skb_peek(&slaver_queue->rel);
	if (skb != NULL)
		pr_info("STAT: s_rel not empty.\n");

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
		failover = 1;
		state = state_failover;
		wake_up_interruptible(&queue);
		pr_info("failover.\n");
	} else if (buf[0]=='r')
		state = state_comparing;
		failover = 0;

	return count;
}

static int __init compare_module_init(void)
{
	int result;
	dev_t dev;

	/* allocate a device id */
	result = alloc_chrdev_region(&dev, cmp_minor, 1, "HA_compare");
	if (result < 0) {
		pr_err("HA_compare: can't get device id.\n");
		return result;
	}
	cmp_major = MAJOR(dev);

	/* setup device */
	result = cmp_setup_cdev(&cmp_dev);
	if (result) {
		pr_err("HA_compare: can't setup device.\n");
		goto err_setup;
	}

	/*
	 * create kernel thread
	 *
	 * TODO:
	 *    One thread for one guest.
	 */
	compare_task = kthread_create(compare_kthread, NULL, "compare/0");
	if (IS_ERR(compare_task)) {
		pr_err("HA_compare: can't create kernel thread\n");
		result = PTR_ERR(compare_task);
		goto err_thread;
	}

	sema_init(&cmp_dev.sem, 1);
	init_waitqueue_head(&queue);

	compare_tcp_init();
	compare_udp_init();

	memset(&statis, 0, sizeof(struct statistic_data));
	proc_entry = create_proc_entry("HA_compare", 0, NULL);
	proc_entry->read_proc = read_proc;
	proc_entry->write_proc = write_proc;

	wake_up_process(compare_task);

	return 0;

err_thread:
	cdev_del(&cmp_dev.cdev);
err_setup:
	unregister_chrdev_region(MKDEV(cmp_major, cmp_minor), 1);

	return result;
}

static void __exit compare_module_exit(void)
{
	kthread_stop(compare_task);

	compare_tcp_fini();
	compare_udp_fini();

	/* del device */
	cdev_del(& cmp_dev.cdev);

	/* free a device id */
	unregister_chrdev_region(MKDEV(cmp_major, cmp_minor), 1);

	remove_proc_entry("HA_compare", NULL);
}
module_init(compare_module_init);
module_exit(compare_module_exit);
MODULE_LICENSE("GPL");
MODULE_INFO(intree, "Y");
