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
#include <linux/module.h>

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
