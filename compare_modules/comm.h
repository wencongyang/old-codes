#ifndef COLO_COMM_H
#define COLO_COMM_H

#include <linux/spinlock_types.h>
#include <linux/types.h>
#include <linux/wait.h>
#include <net/pkt_sched.h>

#include "hash.h"

struct sched_data {
	struct hash_head *blo; /* packets not compared */
	struct sk_buff_head rel; /* packest compared successfully */
	struct Qdisc* sch;
	uint32_t flags;
};

extern struct hash_head *colo_hash_head;
extern struct list_head compare_head;
extern spinlock_t compare_lock;
extern wait_queue_head_t compare_queue;

#endif
