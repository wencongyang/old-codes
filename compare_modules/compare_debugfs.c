/*
 *  COarse-grain LOck-stepping Virtual Machines for Non-stop Service (COLO)
 *  (a.k.a. Fault Tolerance or Continuous Replication)
 *  debugfs to get statistics.
 *
 * Copyright (C) 2014 FUJITSU LIMITED
 *
 * Author: Wen Congyang <wency@cn.fujitsu.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * later.  See the COPYING file in the top-level directory.
 *
 */

#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/module.h>

#include "connections.h"
#include "comm.h"

static struct dentry *colo_root_dir;

//#define NEW_KERNEL

/* ops for read/write u64 */
#ifndef NEW_KERNEL
/* old kernel doesn't have simple_open */
static int simple_open(struct inode *inode, struct file *file)
{
	if (inode->i_private)
		file->private_data = inode->i_private;
	return 0;
}
#endif

static ssize_t
simple_read(struct file *filp, char __user *ubuf,
	    size_t cnt, loff_t *ppos)
{
	unsigned long long *data = filp->private_data;
	char buf[64];
	int len;

	len = sprintf(buf, "%lld\n", *data);

	return simple_read_from_buffer(ubuf, cnt, ppos, buf, len);
}

static ssize_t
simple_write(struct file *filp, const char __user *ubuf,
	     size_t cnt, loff_t *ppos)
{
	unsigned long long *data = filp->private_data;
	unsigned long long new_value;
	int ret;

	ret = kstrtoull_from_user(ubuf, cnt, 10, &new_value);
	if (ret)
		return ret;

	/* only 0 can be written to clear statistics */
	if (new_value)
		return -EINVAL;

	*data = 0;

	return cnt;
}

const struct file_operations colo_u64_ops = {
	.open		= simple_open,
	.read		= simple_read,
	.write		= simple_write,
	.llseek		= generic_file_llseek,
};
EXPORT_SYMBOL(colo_u64_ops);

/* ops for status file */
static int compare_status_show(struct seq_file *m, void *data)
{
	struct if_connections *ics = *(struct if_connections **)m->private;
	struct sk_buff *skb;
	int i, j;
	struct colo_sched_data *master_queue;
	struct colo_sched_data *slave_queue;
	struct connect_info *conn_info;
	int found = 0;

	if (!ics)
		return 0;

	master_queue = ics->master_data;
	slave_queue = ics->slave_data;

	for (i = 0; i < HASH_NR; i++) {
		j = 0;
		list_for_each_entry(conn_info, &ics->entry[i], list) {
			skb = skb_peek(&conn_info->master_queue);
			if (skb != NULL) {
				found = 1;
				break;
			}
			j++;
		}
		if (found)
			break;
	}
	if (found) {
		seq_printf(m, "master compare queue[%d, %d] is not empty.\n",
			   i, j);
		found = 0;
	}

	skb = skb_peek(&master_queue->rel);
	if (skb != NULL)
		seq_printf(m, "master release queue is not empty.\n");

	found = 0;
	for (i = 0; i < HASH_NR; i++) {
		j = 0;
		list_for_each_entry(conn_info, &ics->entry[i], list) {
			skb = skb_peek(&conn_info->slave_queue);
			if (skb != NULL) {
				found = 1;
				break;
			}
			j++;
		}
		if (found)
			break;
	}
	if (found) {
		seq_printf(m, "slave compare queue[%d, %d] is not empty.\n",
			   i, j);
		found = 0;
	}

	skb = skb_peek(&slave_queue->rel);
	if (skb != NULL)
		seq_printf(m, "slave release queue is not empty.\n");

	return 0;
}

static int status_open(struct inode *inode, struct file *file)
{
	return single_open(file, compare_status_show, inode->i_private);
}

static const struct file_operations colo_status_ops = {
	.open		= status_open,
	.read		= seq_read,
	.llseek		= generic_file_llseek,
	.release	= single_release,
};

struct dentry *
colo_create_file(const char *name, const struct file_operations *ops,
		 struct dentry *parent, void *data)
{
	if (!parent)
		parent = colo_root_dir;

	return debugfs_create_file(name, 0644, parent, data, ops);
}

void colo_remove_file(struct dentry *entry)
{
	debugfs_remove(entry);
}
EXPORT_SYMBOL(colo_create_file);
EXPORT_SYMBOL(colo_remove_file);

struct dentry *colo_add_status_file(const char *name,
				    struct if_connections **ics)
{
	return debugfs_create_file(name, 0444, colo_root_dir,
				   ics, &colo_status_ops);
}

int __init colo_debugfs_init(void)
{
	colo_root_dir = debugfs_create_dir("colo", NULL);
	if (!colo_root_dir)
		return -ENOMEM;

	if (IS_ERR(colo_root_dir))
		return PTR_ERR(colo_root_dir);

	return 0;
}

void __exit colo_debugfs_exit(void)
{
	debugfs_remove(colo_root_dir);
}
