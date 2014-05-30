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

#ifndef COMPARE_DEBUGFS_H
#define COMPARE_DEBUGFS_H

extern struct file_operations colo_u64_ops;

extern int __init colo_debugfs_init(void);
extern void __exit colo_debugfs_exit(void);

/* use IS_ERR_OR_NULL to check the return value */
extern struct dentry * colo_create_file(const char *name,
					struct file_operations *fops,
					struct dentry *parent,
					void *data);
extern void colo_remove_file(struct dentry *entry);

#endif
