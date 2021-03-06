/*
 * Xenbus code for netif backend
 *
 * Copyright (C) 2005 Rusty Russell <rusty@rustcorp.com.au>
 * Copyright (C) 2005 XenSource Ltd
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#include "common.h"
#include <linux/wait.h>
#include <xen/events.h>
#include <asm/xen/hypervisor.h>

extern wait_queue_head_t resume_queue;
extern int is_resumed;
extern struct net_device *vif_port_dev;
extern atomic_t dev_opencnt;

static int irqcount = 0;

struct backend_info {
	struct xenbus_device *dev;
	struct xenvif *vif;
	enum xenbus_state frontend_state;
	struct xenbus_watch hotplug_status_watch;
	u8 have_hotplug_status_watch:1;
};

static int connect_rings(struct backend_info *);
static void connect(struct backend_info *);
static void backend_create_xenvif(struct backend_info *be);
static void unregister_hotplug_status_watch(struct backend_info *be);

static void __otherend_changed_handler(struct work_struct*);
struct otherend_changed_work_t {
	struct xenbus_device *dev;
	struct work_struct work;
};
static struct otherend_changed_work_t changed_work;
static irqreturn_t netif_otherend_changed(int irq, void *dev_id, struct pt_regs *ptregs);

static int netback_remove(struct xenbus_device *dev)
{
	struct backend_info *be = dev_get_drvdata(&dev->dev);

	unregister_hotplug_status_watch(be);
	if (be->vif) {
		kobject_uevent(&dev->dev.kobj, KOBJ_OFFLINE);
		xenbus_rm(XBT_NIL, dev->nodename, "hotplug-status");
		xenvif_disconnect(be->vif);
		be->vif = NULL;
	}
	kfree(be);
	dev_set_drvdata(&dev->dev, NULL);
	return 0;
}


/**
 * Entry point to this code when a new device is created.  Allocate the basic
 * structures and switch to InitWait.
 */
static int netback_probe(struct xenbus_device *dev,
			 const struct xenbus_device_id *id)
{
	const char *message;
	struct xenbus_transaction xbt;
	int err;
	int sg;
	struct backend_info *be = kzalloc(sizeof(struct backend_info),
					  GFP_KERNEL);
	if (!be) {
		xenbus_dev_fatal(dev, -ENOMEM,
				 "allocating backend structure");
		return -ENOMEM;
	}

	be->dev = dev;
	dev_set_drvdata(&dev->dev, be);

	sg = 0;

	do {
		err = xenbus_transaction_start(&xbt);
		if (err) {
			xenbus_dev_fatal(dev, err, "starting transaction");
			goto fail;
		}

		err = xenbus_printf(xbt, dev->nodename, "feature-sg", "%d", sg);
		if (err) {
			message = "writing feature-sg";
			goto abort_transaction;
		}

		err = xenbus_printf(xbt, dev->nodename, "feature-gso-tcpv4",
				    "%d", sg);
		if (err) {
			message = "writing feature-gso-tcpv4";
			goto abort_transaction;
		}

		/* We support rx-copy path. */
		err = xenbus_printf(xbt, dev->nodename,
				    "feature-rx-copy", "%d", 1);
		if (err) {
			message = "writing feature-rx-copy";
			goto abort_transaction;
		}

		/*
		 * We don't support rx-flip path (except old guests who don't
		 * grok this feature flag).
		 */
		err = xenbus_printf(xbt, dev->nodename,
				    "feature-rx-flip", "%d", 0);
		if (err) {
			message = "writing feature-rx-flip";
			goto abort_transaction;
		}

		err = xenbus_transaction_end(xbt, 0);
	} while (err == -EAGAIN);

	if (err) {
		xenbus_dev_fatal(dev, err, "completing transaction");
		goto fail;
	}

	err = xenbus_switch_state(dev, XenbusStateInitWait);
	if (err)
		goto fail;

	/* This kicks hotplug scripts, so do it immediately. */
	backend_create_xenvif(be);

	changed_work.dev = dev;
	INIT_WORK(&changed_work.work, __otherend_changed_handler);

	return 0;

abort_transaction:
	xenbus_transaction_end(xbt, 1);
	xenbus_dev_fatal(dev, err, "%s", message);
fail:
	pr_debug("failed");
	netback_remove(dev);
	return err;
}


/*
 * Handle the creation of the hotplug script environment.  We add the script
 * and vif variables to the environment, for the benefit of the vif-* hotplug
 * scripts.
 */
static int netback_uevent(struct xenbus_device *xdev,
			  struct kobj_uevent_env *env)
{
	struct backend_info *be = dev_get_drvdata(&xdev->dev);
	char *val;

	val = xenbus_read(XBT_NIL, xdev->nodename, "script", NULL);
	if (IS_ERR(val)) {
		int err = PTR_ERR(val);
		xenbus_dev_fatal(xdev, err, "reading script");
		return err;
	} else {
		if (add_uevent_var(env, "script=%s", val)) {
			kfree(val);
			return -ENOMEM;
		}
		kfree(val);
	}

	if (!be || !be->vif)
		return 0;

	return add_uevent_var(env, "vif=%s", be->vif->dev->name);
}


static void backend_create_xenvif(struct backend_info *be)
{
	int err;
	long handle;
	int colo_mode;
	struct xenbus_device *dev = be->dev;

	if (be->vif != NULL)
		return;

	err = xenbus_scanf(XBT_NIL, dev->nodename, "handle", "%li", &handle);
	if (err != 1) {
		xenbus_dev_fatal(dev, err, "reading handle");
		return;
	}

	err = xenbus_scanf(XBT_NIL, dev->nodename, "colo_mode", "%i",
			   &colo_mode);
	if (err != 1)
		colo_mode = 0;

	be->vif = xenvif_alloc(&dev->dev, dev->otherend_id, handle);
	if (IS_ERR(be->vif)) {
		err = PTR_ERR(be->vif);
		be->vif = NULL;
		xenbus_dev_fatal(dev, err, "creating interface");
		return;
	}
	be->vif->colo_mode = !!colo_mode;

	kobject_uevent(&dev->dev.kobj, KOBJ_ONLINE);
}


static void disconnect_backend(struct xenbus_device *dev)
{
	struct backend_info *be = dev_get_drvdata(&dev->dev);

	if (be->vif) {
		xenbus_rm(XBT_NIL, dev->nodename, "hotplug-status");
		xenvif_disconnect(be->vif);
		be->vif = NULL;
	}
}

static void disconnect_backend_suspend(struct xenbus_device *dev)
{
	struct backend_info *be = dev_get_drvdata(&dev->dev);

	if (be->vif) {
		xenbus_rm(XBT_NIL, dev->nodename, "hotplug-status");
		xenvif_disconnect_suspend(be->vif);
	}
}

/**
 * Callback received when the frontend's state changes.
 */

struct device *uevent_dev = NULL;
EXPORT_SYMBOL(uevent_dev);
extern int suspended_count;

static void frontend_changed(struct xenbus_device *dev,
			     enum xenbus_state frontend_state)
{
	struct backend_info *be = dev_get_drvdata(&dev->dev);

	pr_debug("frontend state %s", xenbus_strstate(frontend_state));

	be->frontend_state = frontend_state;

	switch (frontend_state) {
	case XenbusStateInitialising:
		if (dev->state == XenbusStateClosed ||
			dev->state == XenbusStateSuspended) {
			printk(KERN_INFO "%s: %s: prepare for reconnect\n",
			       __func__, dev->nodename);
			xenbus_switch_state(dev, XenbusStateInitWait);
		}
		break;

	case XenbusStateInitialised:
		break;

	case XenbusStateConnected:
		if (dev->state == XenbusStateConnected)
			break;
		backend_create_xenvif(be);
		uevent_dev = &dev->dev;
		if (be->vif)
			connect(be);
		vif_port_dev = be->vif->dev;
		is_resumed = 1;
		wake_up_interruptible(&resume_queue);
		break;

	case XenbusStateSuspended:
		suspended_count++;
		is_resumed = 0;
		disconnect_backend_suspend(dev);
		xenbus_switch_state(dev, XenbusStateClosing);
		break;

	case XenbusStateClosing:
		suspended_count = 0;
		irqcount = 0;
		if (be->vif)
			kobject_uevent(&dev->dev.kobj, KOBJ_OFFLINE);
		disconnect_backend(dev);
		vif_port_dev = NULL;
		xenbus_switch_state(dev, XenbusStateClosing);
		break;

	case XenbusStateClosed:
		xenbus_switch_state(dev, XenbusStateClosed);
		if (xenbus_dev_is_online(dev))
			break;
		/* fall through if not online */
	case XenbusStateUnknown:
		device_unregister(&dev->dev);
		break;

	default:
		xenbus_dev_fatal(dev, -EINVAL, "saw state %d at frontend",
				 frontend_state);
		break;
	}
}


static void xen_net_read_rate(struct xenbus_device *dev,
			      unsigned long *bytes, unsigned long *usec)
{
	char *s, *e;
	unsigned long b, u;
	char *ratestr;

	/* Default to unlimited bandwidth. */
	*bytes = ~0UL;
	*usec = 0;

	ratestr = xenbus_read(XBT_NIL, dev->nodename, "rate", NULL);
	if (IS_ERR(ratestr))
		return;

	s = ratestr;
	b = simple_strtoul(s, &e, 10);
	if ((s == e) || (*e != ','))
		goto fail;

	s = e + 1;
	u = simple_strtoul(s, &e, 10);
	if ((s == e) || (*e != '\0'))
		goto fail;

	*bytes = b;
	*usec = u;

	kfree(ratestr);
	return;

 fail:
	pr_warn("Failed to parse network rate limit. Traffic unlimited.\n");
	kfree(ratestr);
}

static int xen_net_read_mac(struct xenbus_device *dev, u8 mac[])
{
	char *s, *e, *macstr;
	int i;

	macstr = s = xenbus_read(XBT_NIL, dev->nodename, "mac", NULL);
	if (IS_ERR(macstr))
		return PTR_ERR(macstr);

	for (i = 0; i < ETH_ALEN; i++) {
		mac[i] = simple_strtoul(s, &e, 16);
		if ((s == e) || (*e != ((i == ETH_ALEN-1) ? '\0' : ':'))) {
			kfree(macstr);
			return -ENOENT;
		}
		s = e+1;
	}

	kfree(macstr);
	return 0;
}

static void unregister_hotplug_status_watch(struct backend_info *be)
{
	if (be->have_hotplug_status_watch) {
		unregister_xenbus_watch(&be->hotplug_status_watch);
		kfree(be->hotplug_status_watch.node);
	}
	be->have_hotplug_status_watch = 0;
}

static void hotplug_status_changed(struct xenbus_watch *watch,
				   const char **vec,
				   unsigned int vec_size)
{
	struct backend_info *be = container_of(watch,
					       struct backend_info,
					       hotplug_status_watch);
	char *str;
	unsigned int len;

	str = xenbus_read(XBT_NIL, be->dev->nodename, "hotplug-status", &len);
	if (IS_ERR(str))
		return;
	if (len == sizeof("connected")-1 && !memcmp(str, "connected", len)) {
		xenbus_switch_state(be->dev, XenbusStateConnected);
		/* Not interested in this watch anymore. */
		unregister_hotplug_status_watch(be);
	}
	kfree(str);
}

static void connect(struct backend_info *be)
{
	int err;
	struct xenbus_device *dev = be->dev;

	err = connect_rings(be);
	if (err) {
		printk("COLO: error in connect rings.\n");
		return;
	}

	err = xen_net_read_mac(dev, be->vif->fe_dev_addr);
	if (err) {
		xenbus_dev_fatal(dev, err, "parsing %s/mac", dev->nodename);
		return;
	}

	xen_net_read_rate(dev, &be->vif->credit_bytes,
			  &be->vif->credit_usec);
	be->vif->remaining_credit = be->vif->credit_bytes;

	unregister_hotplug_status_watch(be);
	err = xenbus_watch_pathfmt(dev, &be->hotplug_status_watch,
				   hotplug_status_changed,
				   "%s/%s", dev->nodename, "hotplug-status");
	if (err) {
		/* Switch now, since we can't do a watch. */
		xenbus_switch_state(dev, XenbusStateConnected);
	} else {
		be->have_hotplug_status_watch = 1;
	}

	if (suspended_count) {
		dev->state = XenbusStateConnected;
		suspended_count++;
	}

	netif_wake_queue(be->vif->dev);
}

static void read_ringref_from_xen(int *rx, int *tx, int *evtchn)
{
	struct rdwt_data arg;
	arg.flag = 0;
	HYPERVISOR_rdwt_data_op(&arg);
	(*rx) = arg.rx_ref;
	(*tx) = arg.tx_ref;
	(*evtchn) = arg.vnif_evtchn;
}

static int connect_rings(struct backend_info *be)
{
	struct xenvif *vif = be->vif;
	struct xenbus_device *dev = be->dev;
	unsigned long tx_ring_ref, rx_ring_ref;
	unsigned int evtchn, rx_copy, fast;
	int err=0;
	int val;
	static int which_side = 0;

	if (which_side == 0) {
		which_side = HYPERVISOR_which_side_op(0);
		printk("COLO: which_side=%d\n", which_side);
	}

	//err = xenbus_gather(XBT_NIL, dev->otherend,
	//		    "tx-ring-ref", "%lu", &tx_ring_ref,
	//		    "rx-ring-ref", "%lu", &rx_ring_ref,
	//		    "event-channel", "%u", &evtchn, NULL);	

	read_ringref_from_xen(&rx_ring_ref, &tx_ring_ref, &evtchn);
	printk("COLO: Read ringref from xen: rx=%d, tx=%d, evtchn=%d.\n", 
		rx_ring_ref, tx_ring_ref, evtchn);

	if ( (which_side == -1 && suspended_count==0)		//master side
		|| (which_side > 0 && suspended_count==0) )	//slaver side
	{

		if (err) {
			xenbus_dev_fatal(dev, err,
					 "reading %s/ring-ref and event-channel",
					 dev->otherend);
			return err;
		}

		err = xenbus_scanf(XBT_NIL, dev->otherend, "request-rx-copy", "%u",
				   &rx_copy);
		if (err == -ENOENT) {
			err = 0;
			rx_copy = 0;
		}
		if (err < 0) {
			xenbus_dev_fatal(dev, err, "reading %s/request-rx-copy",
					 dev->otherend);
			return err;
		}
		if (!rx_copy)
			return -EOPNOTSUPP;

		if (vif->dev->tx_queue_len != 0) {
			if (xenbus_scanf(XBT_NIL, dev->otherend,
					 "feature-rx-notify", "%d", &val) < 0)
				val = 0;
			if (val)
				vif->can_queue = 1;
			else
				/* Must be non-zero for pfifo_fast to work. */
				vif->dev->tx_queue_len = 1;
		}

		if (xenbus_scanf(XBT_NIL, dev->otherend, "feature-sg",
				 "%d", &val) < 0)
			val = 0;
		vif->can_sg = !!val;

		if (xenbus_scanf(XBT_NIL, dev->otherend, "feature-gso-tcpv4",
				 "%d", &val) < 0)
			val = 0;
		vif->gso = !!val;

		if (xenbus_scanf(XBT_NIL, dev->otherend, "feature-gso-tcpv4-prefix",
				 "%d", &val) < 0)
			val = 0;
		vif->gso_prefix = !!val;

		if (xenbus_scanf(XBT_NIL, dev->otherend, "feature-no-csum-offload",
				 "%d", &val) < 0)
			val = 0;
		vif->csum = !val;
	}

	/* Map the shared frame, irq etc. */
	err = xenvif_connect(vif, tx_ring_ref, rx_ring_ref, evtchn);
	if (err) {
		xenbus_dev_fatal(dev, err,
				 "mapping shared-frames %lu/%lu port %u",
				 tx_ring_ref, rx_ring_ref, evtchn);
		return err;
	}

	printk("COLO: wich_side=%d, suspended_count=%d.\n", which_side, suspended_count);
	if ( (which_side == -1 && suspended_count == 1)		//master side
		|| (which_side > 0 && suspended_count==0) ) {	//slaver side
		printk("COLO: bind fast channel...\n");
		err = xenbus_scanf(XBT_NIL, dev->otherend, "fast-channel", "%u", &fast);
		if (err < 0) {
			printk("COLO: read fast-channel error.\n");
			return err;
		}

		irqcount = 0;
		err = bind_interdomain_evtchn_to_irqhandler(
			vif->domid, fast, netif_otherend_changed, 0,
			vif->dev->name, vif);
		if (err < 0) {
			printk("COLO: error in bind_interdomain_evtchn_to_irqhandler.\n");
			return err;
		}
		vif->fast = err;
	}

	return 0;
}

static irqreturn_t netif_otherend_changed(int irq, void *dev_id, struct pt_regs *ptregs)
{
	irqcount++;
	if (irqcount==1)
		return IRQ_HANDLED;

	printk("COLO: otherend changed interrupt.\n");
	schedule_work(&changed_work.work);
	return IRQ_HANDLED;
}

static void __otherend_changed_handler(struct work_struct *work)
{
	struct otherend_changed_work_t *wc = container_of(work,
			struct otherend_changed_work_t, work);
	struct xenbus_device *dev = wc->dev;
	struct backend_info *be = dev_get_drvdata(&dev->dev);
	printk("COLO: in fast changed, state=%d.\n\n", dev->state);

	switch (dev->state) {
	case XenbusStateClosing:
	case XenbusStateClosed:
		dev->state = XenbusStateInitWait;
		printk("COLO: notify remote_via irq in closing.\n");
		notify_remote_via_irq(be->vif->fast);
		break;

	case XenbusStateInitWait:
		if (be->vif)
			connect(be);
		if (atomic_add_return(1, &dev_opencnt) == 2) {
			is_resumed = 1;
			wake_up_interruptible(&resume_queue);
			printk("COLO: wake up resume.\n");
		}
		break;

	case XenbusStateConnected:
		suspended_count++;
		is_resumed = 0;
		disconnect_backend_suspend(dev);
		dev->state = XenbusStateClosing;
		notify_remote_via_irq(be->vif->fast);
		break;
	}
}


/* ** Driver Registration ** */


static const struct xenbus_device_id netback_ids[] = {
	{ "vif" },
	{ "" }
};


static struct xenbus_driver netback = {
	.name = "vif",
	.owner = THIS_MODULE,
	.ids = netback_ids,
	.probe = netback_probe,
	.remove = netback_remove,
	.uevent = netback_uevent,
	.otherend_changed = frontend_changed,
};

int xenvif_xenbus_init(void)
{
	init_waitqueue_head(&resume_queue);
	return xenbus_register_backend(&netback);
}
