#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cdev.h>
#include <linux/skbuff.h>

#include "comm.h"
#include "compare.h"
#include "ip_fragment.h"
#include "ipv4_fragment.h"

#define COMP_IOC_MAGIC 		'k'
#define COMP_IOCTWAIT 		_IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTSUSPEND 	_IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME 	_IO(COMP_IOC_MAGIC, 2)

struct colo_device {
	struct cdev cdev;
	struct semaphore sem;
} colo_dev;

static dev_t colo_devno;

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

	if (eth->h_proto != htons(ETH_P_IP))
		return;

	ip = (struct iphdr *)(skb->data + sizeof(*eth));
	ipv4_update_compare_info(&conn_info->m_info, ip, skb);
}

static void move_master_queue(struct if_connections *ics)
{
	int i;
	struct sk_buff *skb;
	struct connect_info *conn_info;

	if (unlikely(ics == NULL)) {
		pr_warn("ics is NULL when move_master_queue\n");
		return;
	}

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

	if (unlikely(ics == NULL)) {
		pr_warn("ics is NULL when release queue\n");
		return;
	}

	skb = skb_dequeue(&ics->wait_for_release);
	while (skb != NULL) {
		flag = 1;
		skb_queue_tail(&ics->master_data->rel, skb);
		skb = skb_dequeue(&ics->wait_for_release);
	}

	if (flag)
		netif_schedule_queue(ics->master_data->sch->dev_queue);
}

int cmp_open(struct inode *inode, struct file *filp)
{
	struct colo_device *dev;

	dev = container_of(inode->i_cdev, struct colo_device, cdev);
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
	struct colo_device *dev;

	dev = container_of(inode->i_cdev, struct colo_device, cdev);
	up(&dev->sem);
	pr_notice("HA_compare: close.\n");

	return 0;
}

long cmp_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	int ret;

	switch(cmd) {
	case COMP_IOCTWAIT:
		/* wait for a new checkpoint */
#if 1
		ret = wait_event_interruptible_timeout(queue, state != state_comparing, arg);
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

		break;
	}

	return 0;
}

struct file_operations cmp_fops = {
	.owner = THIS_MODULE,
	.open = cmp_open,
	.unlocked_ioctl = cmp_ioctl,
	.release = cmp_release,
};

static int setup_colo_cdev(struct colo_device *dev)
{
	int err;

	cdev_init(&dev->cdev, &cmp_fops);
	dev->cdev.owner = THIS_MODULE;
	dev->cdev.ops = &cmp_fops;
	err = cdev_add(&dev->cdev, colo_devno, 1);

	if (err) {
		pr_warn("HA_compare: Error %d adding devices.\n", err);
		return -1;
	}

	return 0;
}

int colo_dev_init(void)
{
	int ret;

	/* allocate a device id */
	ret = alloc_chrdev_region(&colo_devno, 0, 1, "HA_compare");
	if (ret < 0) {
		pr_err("HA_compare: can't get device id.\n");
		return ret;
	}

	/* setup device */
	ret = setup_colo_cdev(&colo_dev);
	if (ret) {
		pr_err("HA_compare: can't setup device.\n");
		unregister_chrdev_region(colo_devno, 1);
		return ret;
	}

	sema_init(&colo_dev.sem, 1);

	return 0;
}

void colo_dev_fini(void)
{
	/* del device */
	cdev_del(&colo_dev.cdev);

	/* free a device id */
	unregister_chrdev_region(colo_devno, 1);
}
