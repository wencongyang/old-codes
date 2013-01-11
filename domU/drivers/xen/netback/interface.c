/******************************************************************************
 * arch/xen/drivers/netif/backend/interface.c
 * 
 * Network-device interface management.
 * 
 * Copyright (c) 2004-2005, Keir Fraser
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation; or, when distributed
 * separately from the Linux kernel or incorporated into other
 * software packages, subject to the following license:
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this source file (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy, modify,
 * merge, publish, distribute, sublicense, and/or sell copies of the Software,
 * and to permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */

#include "common.h"
#include <linux/ethtool.h>
#include <linux/rtnetlink.h>
#include <linux/delay.h>
#include <linux/vmalloc.h>
#include <xen/evtchn.h>

/*
 * Module parameter 'queue_length':
 * 
 * Enables queuing in the network stack when a client has run out of receive
 * descriptors. Although this feature can improve receive bandwidth by avoiding
 * packet loss, it can also result in packets sitting in the 'tx_queue' for
 * unbounded time. This is bad if those packets hold onto foreign resources.
 * For example, consider a packet that holds onto resources belonging to the
 * guest for which it is queued (e.g., packet received on vif1.0, destined for
 * vif1.1 which is not activated in the guest): in this situation the guest
 * will never be destroyed, unless vif1.1 is taken down. To avoid this, we
 * run a timer (tx_queue_timeout) to drain the queue when the interface is
 * blocked.
 */
static unsigned long netbk_queue_length = 32;
module_param_named(queue_length, netbk_queue_length, ulong, 0644);

static void __netif_up(netif_t *netif)
{
	enable_irq(netif->irq);
	netif_schedule_work(netif);
}

static void __netif_down(netif_t *netif)
{
	disable_irq(netif->irq);
	netif_deschedule_work(netif);
}

static int net_open(struct net_device *dev)
{
	netif_t *netif = netdev_priv(dev);
	if (netback_carrier_ok(netif)) {
		__netif_up(netif);
		netif_start_queue(dev);
	}
	return 0;
}

static int net_close(struct net_device *dev)
{
	netif_t *netif = netdev_priv(dev);
	if (netback_carrier_ok(netif))
		__netif_down(netif);
	netif_stop_queue(dev);
	return 0;
}

static int netbk_change_mtu(struct net_device *dev, int mtu)
{
	int max = netbk_can_sg(dev) ? 65535 - ETH_HLEN : ETH_DATA_LEN;

	if (mtu > max)
		return -EINVAL;
	dev->mtu = mtu;
	return 0;
}

void netif_set_features(netif_t *netif)
{
	struct net_device *dev = netif->dev;
	int features = dev->features;

	if (netif->can_sg)
		features |= NETIF_F_SG;
	if (netif->gso)
		features |= NETIF_F_TSO;
	if (netif->csum)
		features |= NETIF_F_IP_CSUM;

	features &= ~(netif->features_disabled);

	if (!(features & NETIF_F_SG) && dev->mtu > ETH_DATA_LEN)
		dev->mtu = ETH_DATA_LEN;

	dev->features = features;
}

static int netbk_set_tx_csum(struct net_device *dev, u32 data)
{
	netif_t *netif = netdev_priv(dev);
	if (data) {
		if (!netif->csum)
			return -ENOSYS;
		netif->features_disabled &= ~NETIF_F_IP_CSUM;
	} else {
		netif->features_disabled |= NETIF_F_IP_CSUM;
	}

	netif_set_features(netif);
	return 0;
}

static int netbk_set_sg(struct net_device *dev, u32 data)
{
	netif_t *netif = netdev_priv(dev);
	if (data) {
		if (!netif->can_sg)
			return -ENOSYS;
		netif->features_disabled &= ~NETIF_F_SG;
	} else {
		netif->features_disabled |= NETIF_F_SG;
	}

	netif_set_features(netif);
	return 0;
}

static int netbk_set_tso(struct net_device *dev, u32 data)
{
	netif_t *netif = netdev_priv(dev);
	if (data) {
		if (!netif->gso)
			return -ENOSYS;
		netif->features_disabled &= ~NETIF_F_TSO;
	} else {
		netif->features_disabled |= NETIF_F_TSO;
	}

	netif_set_features(netif);
	return 0;
}

static void netbk_get_drvinfo(struct net_device *dev,
			      struct ethtool_drvinfo *info)
{
	strcpy(info->driver, "netbk");
	strcpy(info->bus_info, dev->class_dev.dev->bus_id);
}

static const struct netif_stat {
	char name[ETH_GSTRING_LEN];
	u16 offset;
} netbk_stats[] = {
	{ "copied_skbs", offsetof(netif_t, nr_copied_skbs) / sizeof(long) },
};

static int netbk_get_stats_count(struct net_device *dev)
{
	return ARRAY_SIZE(netbk_stats);
}

static void netbk_get_ethtool_stats(struct net_device *dev,
				   struct ethtool_stats *stats, u64 * data)
{
	unsigned long *np = netdev_priv(dev);
	int i;

	for (i = 0; i < ARRAY_SIZE(netbk_stats); i++)
		data[i] = np[netbk_stats[i].offset];
}

static void netbk_get_strings(struct net_device *dev, u32 stringset, u8 * data)
{
	int i;

	switch (stringset) {
	case ETH_SS_STATS:
		for (i = 0; i < ARRAY_SIZE(netbk_stats); i++)
			memcpy(data + i * ETH_GSTRING_LEN,
			       netbk_stats[i].name, ETH_GSTRING_LEN);
		break;
	}
}

static struct ethtool_ops network_ethtool_ops =
{
	.get_drvinfo = netbk_get_drvinfo,

	.get_tx_csum = ethtool_op_get_tx_csum,
	.set_tx_csum = netbk_set_tx_csum,
	.get_sg = ethtool_op_get_sg,
	.set_sg = netbk_set_sg,
	.get_tso = ethtool_op_get_tso,
	.set_tso = netbk_set_tso,
	.get_link = ethtool_op_get_link,

	.get_stats_count = netbk_get_stats_count,
	.get_ethtool_stats = netbk_get_ethtool_stats,
	.get_strings = netbk_get_strings,
};

netif_t *netif_alloc(struct device *parent, domid_t domid, unsigned int handle)
{
	int err = 0;
	struct net_device *dev;
	netif_t *netif;
	char name[IFNAMSIZ] = {};

	snprintf(name, IFNAMSIZ - 1, "vif%u.%u", domid, handle);
	dev = alloc_netdev(sizeof(netif_t), name, ether_setup);
	if (dev == NULL) {
		DPRINTK("Could not create netif: out of memory\n");
		return ERR_PTR(-ENOMEM);
	}

	SET_NETDEV_DEV(dev, parent);

	netif = netdev_priv(dev);
	memset(netif, 0, sizeof(*netif));
	netif->domid  = domid;
	netif->handle = handle;
	netif->can_sg = 1;
	netif->csum = 1;
	atomic_set(&netif->refcnt, 1);
	init_waitqueue_head(&netif->waiting_to_free);
	netif->dev = dev;

	netback_carrier_off(netif);

	netif->credit_bytes = netif->remaining_credit = ~0UL;
	netif->credit_usec  = 0UL;
	init_timer(&netif->credit_timeout);
	/* Initialize 'expires' now: it's used to track the credit window. */
	netif->credit_timeout.expires = jiffies;

	init_timer(&netif->tx_queue_timeout);

	dev->hard_start_xmit = netif_be_start_xmit;
	dev->get_stats       = netif_be_get_stats;
	dev->open            = net_open;
	dev->stop            = net_close;
	dev->change_mtu	     = netbk_change_mtu;

	netif_set_features(netif);

	SET_ETHTOOL_OPS(dev, &network_ethtool_ops);

	dev->tx_queue_len = netbk_queue_length;

	/*
	 * Initialise a dummy MAC address. We choose the numerically
	 * largest non-broadcast address to prevent the address getting
	 * stolen by an Ethernet bridge for STP purposes.
	 * (FE:FF:FF:FF:FF:FF)
	 */ 
	memset(dev->dev_addr, 0xFF, ETH_ALEN);
	dev->dev_addr[0] &= ~0x01;

	rtnl_lock();
	err = register_netdevice(dev);
	rtnl_unlock();
	if (err) {
		DPRINTK("Could not register new net device %s: err=%d\n",
			dev->name, err);
		free_netdev(dev);
		return ERR_PTR(err);
	}

	DPRINTK("Successfully created netif\n");
	return netif;
}

int netif_map(struct backend_info *be, grant_ref_t tx_ring_ref,
	      grant_ref_t rx_ring_ref, evtchn_port_t evtchn)
{
	netif_t *netif = be->netif;
	struct vm_struct *area;
	int err = -ENOMEM;
	netif_tx_sring_t *txs;
	netif_rx_sring_t *rxs;

	/* Already connected through? */
	if (netif->irq)
		return 0;

	area = xenbus_map_ring_valloc(be->dev, tx_ring_ref);
	if (IS_ERR(area))
		return PTR_ERR(area);
	netif->tx_comms_area = area;
	area = xenbus_map_ring_valloc(be->dev, rx_ring_ref);
	if (IS_ERR(area)) {
		err = PTR_ERR(area);
		goto err_rx;
	}
	netif->rx_comms_area = area;

	err = bind_interdomain_evtchn_to_irqhandler(
		netif->domid, evtchn, netif_be_int, 0,
		netif->dev->name, netif);
	if (err < 0)
		goto err_hypervisor;
	netif->irq = err;
	disable_irq(netif->irq);

	txs = (netif_tx_sring_t *)netif->tx_comms_area->addr;
	BACK_RING_INIT(&netif->tx, txs, PAGE_SIZE);

	rxs = (netif_rx_sring_t *)
		((char *)netif->rx_comms_area->addr);
	BACK_RING_INIT(&netif->rx, rxs, PAGE_SIZE);

	netif->rx_req_cons_peek = 0;

	netif_get(netif);

	rtnl_lock();
	netback_carrier_on(netif);
	if (netif_running(netif->dev))
		__netif_up(netif);
	rtnl_unlock();

	return 0;
err_hypervisor:
	xenbus_unmap_ring_vfree(be->dev, netif->rx_comms_area);
err_rx:
	xenbus_unmap_ring_vfree(be->dev, netif->tx_comms_area);
	return err;
}

void netif_disconnect(struct backend_info *be)
{
	netif_t *netif = be->netif;

	if (netback_carrier_ok(netif)) {
		rtnl_lock();
		netback_carrier_off(netif);
		netif_carrier_off(netif->dev); /* discard queued packets */
		if (netif_running(netif->dev))
			__netif_down(netif);
		rtnl_unlock();
		netif_put(netif);
	}

	atomic_dec(&netif->refcnt);
	wait_event(netif->waiting_to_free, atomic_read(&netif->refcnt) == 0);

	del_timer_sync(&netif->credit_timeout);
	del_timer_sync(&netif->tx_queue_timeout);

	if (netif->irq)
		unbind_from_irqhandler(netif->irq, netif);
	
	unregister_netdev(netif->dev);

	if (netif->tx.sring) {
		xenbus_unmap_ring_vfree(be->dev, netif->tx_comms_area);
		xenbus_unmap_ring_vfree(be->dev, netif->rx_comms_area);
	}

	free_netdev(netif->dev);
}
