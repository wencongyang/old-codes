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
#include "ip_fragment.h"
#include "ipv4_fragment.h"

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

static void clear_slaver_queue(struct if_connections *ics);
static void move_master_queue(struct if_connections *ics);
static void release_queue(struct if_connections *ics);

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
		pr_warn("HA_compare: Error %d adding devices.\n", err);
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
		pr_notice("HA_compare: another client allready opened this dev.\n");
		return -1;
	}

	pr_notice("HA_compare: open successfully.\n");
	filp->private_data = dev;
	return 0;
}

int cmp_release(struct inode *inode, struct file *filp)
{
	struct _cmp_dev *dev;

	dev = container_of(inode->i_cdev, struct _cmp_dev, cdev);
	up(&dev->sem);
	pr_notice("HA_compare: close.\n");

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

		pr_notice("HA_compare: --------start a new checkpoint.\n");

		break;
	case COMP_IOCTSUSPEND:
		/*  Both side suspend the VM, at this point, no packets will
		 *  send out from VM, so block skb queues(master&slaver) are
		 *  stable. Move master block queue to a temporary queue, then
		 *  they will be released when checkpoint ends. For slaver
		 *  block queue, just drop them.
		 */
		pr_notice("HA_compare: --------both side suspended.\n");

		move_master_queue(colo_ics);
		clear_slaver_queue(colo_ics);
		break;
	case COMP_IOCTRESUME:
		/*
		 *  Checkpoint finish, relese skb in temporary queue
		 */
		pr_notice("HA_compare: --------checkpoint finish.\n");
		release_queue(colo_ics);
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

	pr_warn("HA_compare:[ARP] ar_hrd=%u, ar_pro=%u\n",
		htons(arp->ar_hrd), htons(arp->ar_pro));
	pr_warn("HA_compare:[ARP] ar_hln=%u, ar_pln=%u, ar_op=%u\n",
		arp->ar_hln, arp->ar_pln, htons(arp->ar_op));
	if (htons(arp->ar_op) == ARPOP_REPLY || htons(arp->ar_op) == ARPOP_REQUEST) {
		temp = (struct arp_reply *)((char*)arp + sizeof(struct arphdr));
		pr_warn("HA_compare:[ARP] ar_sha: %pM, ar_sip: %pI4\n", temp->ar_sha, temp->ar_sip);
		pr_warn("HA_compare:[ARP] ar_tha: %pM, ar_tip: %pI4\n", temp->ar_tha, temp->ar_tip);
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

uint32_t compare_other_packet(void *m, void *s, int length)
{
	return memcmp(m, s, length) ? CHECKPOINT : SAME_PACKET;
}

static uint32_t
compare_arp_packet(struct compare_info *m, struct compare_info *s)
{
	if (m->length != s->length)
		return CHECKPOINT;

	/* TODO */
	return compare_other_packet(m->packet, s->packet, m->length);
}

static uint32_t
compare_skb(struct compare_info *m, struct compare_info *s)
{
	uint32_t ret;

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
		if (ret & CHECKPOINT) {
			pr_warn("HA_compare: master packet, len=%d\n", m->length);
			debug_print_arp(m->packet);
			pr_warn("HA_compare: slaver packet, len=%d\n", s->length);
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
	if (ret & CHECKPOINT) {
		pr_warn("HA_compare: compare_xxx_packet() fails %04x\n", ntohs(m->eth->h_proto));
		goto different;
	}

	if (ret == SAME_PACKET)
		same_count++;
	return ret;

different:
	reset_compare_status();
	return CHECKPOINT;
}

static void clear_slaver_queue(struct if_connections *ics)
{
	int i;
	struct sk_buff *skb;
	struct connect_info *conn_info;

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry(conn_info, &ics->entry[i], list) {
			skb = skb_dequeue(&conn_info->slaver_queue);
			while (skb != NULL) {
				skb_queue_tail(&conn_info->ics->slaver_data->rel, skb);
				skb = skb_dequeue(&conn_info->slaver_queue);
			}
		}
	}

	/* clear ip fragments */
	clear_ipv4_frags(&ics->slaver_data->ipv4_frags);

	/* copy ipv4 fragments from master */
	copy_ipv4_frags(&ics->master_data->ipv4_frags,
			&ics->slaver_data->ipv4_frags);
}

static void update_compare_info(struct connect_info *conn_info, struct sk_buff *skb)
{
	struct ethhdr *eth = (struct ethhdr *)skb->data;
	struct iphdr *ip;

	if (htons(eth->h_proto) != ETH_P_IP)
		return;

	ip = (struct iphdr *)(skb->data + sizeof(*eth));
	ip_update_compare_info(&conn_info->m_info, ip, skb);
}

static void move_master_queue(struct if_connections *ics)
{
	int i;
	struct sk_buff *skb;
	struct connect_info *conn_info;

	for (i = 0; i < HASH_NR; i++) {
		list_for_each_entry(conn_info, &ics->entry[i], list) {
			skb = skb_dequeue(&conn_info->master_queue);
			while (skb != NULL) {
				update_compare_info(conn_info, skb);
				skb_queue_tail(&ics->wait_for_release, skb);
				skb = skb_dequeue(&conn_info->master_queue);
			}

			/*
			 * copy compare info:
			 *      We call this function when a new checkpoint is
			 *      finished. The status of master and slaver is
			 *      the same. So slaver's compare info shoule be
			 *      the same as master's.
			 */
			memcpy(&conn_info->s_info, &conn_info->m_info,
				sizeof(conn_info->s_info));
		}
	}
}

static void release_queue(struct if_connections *ics)
{
	struct sk_buff *skb;
	int flag = 0;

	skb = skb_dequeue(&ics->wait_for_release);
	while (skb != NULL) {
		flag = 1;
		++rel_count;
		skb_queue_tail(&ics->master_data->rel, skb);
		skb = skb_dequeue(&ics->wait_for_release);
	}

	if (flag)
		netif_schedule_queue(ics->master_data->sch->dev_queue);
}

static void release_skb(struct sk_buff_head *head, struct sk_buff *skb)
{
	struct sk_buff *next;

	if (!(FRAG_CB(skb)->flags & IS_FRAGMENT)) {
		skb_queue_tail(head, skb);
		return;
	}

	next = skb_shinfo(skb)->frag_list;
	skb_shinfo(skb)->frag_list = NULL;
	do {
		skb_queue_tail(head, skb);
		skb = next;
		if (next)
			next = next->next;
	} while (skb != NULL);
}

static uint32_t compare_one_skb(struct compare_info *m, struct compare_info *s)
{
	struct sk_buff *skb;
	struct compare_info *info = NULL;
	struct compare_info *other_info = NULL;
	uint32_t ret = 0;

	if (m->skb) {
		info = m;
		other_info = s;
		ret = BYPASS_MASTER;
	} else if (s->skb) {
		info = s;
		other_info = m;
		ret = DROP_SLAVER;
	} else
		BUG();

	skb = info->skb;

	info->eth = (struct ethhdr *)info->skb->data;
	info->length = info->skb->len;

	if (unlikely(info->length < sizeof(struct ethhdr))) {
		pr_warn("HA_compare: %s packet is corrupted\n",
			m->skb ? "master" : "slaver");
		goto err;
	}

	info->packet = (char *)info->eth + sizeof(struct ethhdr);
	info->length -= sizeof(struct ethhdr);

	if (ntohs(info->eth->h_proto) != ETH_P_IP)
		goto unsupported;

	/* clear other_info to avoid unexpected error */
	other_info->eth = NULL;
	other_info->packet = NULL;
	other_info->length = 0;

	return ipv4_compare_one_packet(m, s);

err:
	return ret;

unsupported:
	return 0;
}

static void compare(struct connect_info *conn_info)
{
	struct sk_buff *skb_m;
	struct sk_buff *skb_s;
	int ret;
	struct compare_info info_m, info_s;
	struct timespec start, end, delta;
	struct if_connections *ics = conn_info->ics;
	bool skip_compare_one = false;

	getnstimeofday(&start);
	statis.update++;

	if (in_softirq())
		statis.in_soft_irq++;

	while (1) {
		if (state != state_comparing)
			break;

		skb_m = skb_dequeue(&conn_info->master_queue);
		skb_s = skb_dequeue(&conn_info->slaver_queue);

		if (!skb_m && !skb_s)
			break;

		if ((!skb_m || !skb_s) && skip_compare_one) {
			/* We have checked skb_m or skb_s */
			if (skb_m)
				skb_queue_head(&conn_info->master_queue, skb_m);

			if (skb_s)
				skb_queue_head(&conn_info->slaver_queue, skb_s);
			break;
		}

		info_m.skb = skb_m;
		info_s.skb = skb_s;
		info_m.private_data = &conn_info->m_info;
		info_s.private_data = &conn_info->s_info;
		if (!skb_m || !skb_s)
			ret = compare_one_skb(&info_m, &info_s);
		else
			ret = compare_skb(&info_m, &info_s);
		if (!(ret & CHECKPOINT)) {
			if (!skb_m && info_m.skb)
				skb_m = info_m.skb;

			if (likely(ret & BYPASS_MASTER)) {
				release_skb(&ics->master_data->rel, skb_m);
				netif_schedule_queue(ics->master_data->sch->dev_queue);
			} else if (skb_m) {
				skb_queue_head(&conn_info->master_queue, skb_m);
			}

			if (!skb_s && info_s.skb)
				skb_s = info_s.skb;

			if (likely(ret & DROP_SLAVER)) {
				release_skb(&ics->slaver_data->rel, skb_s);
				netif_schedule_queue(ics->slaver_data->sch->dev_queue);
			} else if (skb_s) {
				skb_queue_head(&conn_info->slaver_queue, skb_s);
			}
			//pr_info("netif_schedule%u.\n", cnt);
			if (!ret)
				skip_compare_one = true;
			else
				skip_compare_one = false;
		} else {
			/*
			 *  Put makster's skb to temporary queue, drop slaver's.
			 */
			release_skb(&ics->wait_for_release, skb_m);

			release_skb(&ics->slaver_data->rel, skb_s);

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

static struct connect_info *get_connect_info(void)
{
	struct connect_info *conn_info = NULL;

	spin_lock_bh(&compare_lock);
	if (list_empty(&compare_head))
		goto out;

	conn_info = list_first_entry(&compare_head, struct connect_info,
				 compare_list);
	list_del_init(&conn_info->compare_list);
out:
	spin_unlock_bh(&compare_lock);
	return conn_info;
}

static int compare_kthread(void *data)
{
	struct connect_info *conn_info;

	while(!kthread_should_stop()) {
		wait_event_interruptible(compare_queue,
					 !list_empty(&compare_head) ||
					 kthread_should_stop());

		if (kthread_should_stop())
			break;

		while(!list_empty(&compare_head)) {
			conn_info = get_connect_info();
			if (conn_info)
				compare(conn_info);

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
	struct colo_sched_data *master_queue = colo_ics->master_data;
	struct colo_sched_data *slaver_queue = colo_ics->slaver_data;
	struct connect_info *conn_info;

	pr_info("STAT: update=%u, in_soft_irq=%u, total_time=%llu, last_time=%llu, max_time=%llu\n",
		statis.update, statis.in_soft_irq, statis.total_time, statis.last_time, statis.max_time);
	pr_info("STAT Debug info:\n");
	pr_info("\nSTAT: status=%d.\n", state);

	for (i = 0; i < HASH_NR; i++) {
		j = 0;
		list_for_each_entry(conn_info, &master_queue->ics->entry[i], list) {
			skb = skb_peek(&conn_info->master_queue);
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
		list_for_each_entry(conn_info, &slaver_queue->ics->entry[i], list) {
			skb = skb_peek(&conn_info->slaver_queue);
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
