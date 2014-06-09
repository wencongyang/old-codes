/* 
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

#include <linux/version.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/signal.h>
#include <linux/sched.h>
#include <linux/interrupt.h>
#include <linux/tty.h>
#include <linux/tty_flip.h>
#include <linux/serial.h>
#include <linux/major.h>
#include <linux/ptrace.h>
#include <linux/ioport.h>
#include <linux/mm.h>
#include <linux/slab.h>

#include <asm/hypervisor.h>
#include <xen/evtchn.h>
#include <xen/xencons.h>
#include <linux/wait.h>
#include <linux/interrupt.h>
#include <linux/sched.h>
#include <linux/err.h>
#include <xen/interface/io/console.h>
#include <linux/console.h>

static int xencons_irq;
extern int HA_xencons_evtchn;
extern int HA_xencons_irq;

static wait_queue_head_t xencons_suspend_queue;

static inline struct xencons_interface *xencons_interface(void)
{
	return mfn_to_virt(xen_start_info->console.domU.mfn);
}

static inline void notify_daemon(void)
{
	/* Use evtchn: this is called early, before irq is set up. */
	notify_remote_via_evtchn(xen_start_info->console.domU.evtchn);
}

int xencons_ring_send(const char *data, unsigned len)
{
	int sent = 0;
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;

	cons = intf->out_cons;
	prod = intf->out_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->out));

	while ((sent < len) && ((prod - cons) < sizeof(intf->out)))
		intf->out[MASK_XENCONS_IDX(prod++, intf->out)] = data[sent++];

	wmb();
	intf->out_prod = prod;

	notify_daemon();

	return sent;
}

static irqreturn_t handle_input(int irq, void *unused, struct pt_regs *regs)
{
	struct xencons_interface *intf = xencons_interface();
	XENCONS_RING_IDX cons, prod;

	cons = intf->in_cons;
	prod = intf->in_prod;
	mb();
	BUG_ON((prod - cons) > sizeof(intf->in));

	while (cons != prod) {
		xencons_rx(intf->in+MASK_XENCONS_IDX(cons,intf->in), 1, regs);
		cons++;
	}

	mb();
	intf->in_cons = cons;

	notify_daemon();

	xencons_tx();

	mb();
	if (intf->out_cons == intf->out_prod)
		wake_up(&xencons_suspend_queue);

	return IRQ_HANDLED;
}

int xencons_ring_init(void)
{
	int irq, init = 1;

	if (xencons_irq) {
		unbind_from_irqhandler(xencons_irq, NULL);
		init = 0;
	}
	xencons_irq = 0;

	if (!is_running_on_xen() ||
	    is_initial_xendomain() ||
	    !xen_start_info->console.domU.evtchn)
		return -ENODEV;

	if (init)
		init_waitqueue_head(&xencons_suspend_queue);

	irq = bind_caller_port_to_irqhandler(
		xen_start_info->console.domU.evtchn,
		handle_input, 0, "xencons", NULL);
	if (irq < 0) {
		printk(KERN_ERR "XEN console request irq failed %i\n", irq);
		return irq;
	}

	xencons_irq = irq;
	HA_xencons_irq = irq;
	HA_xencons_evtchn = xen_start_info->console.domU.evtchn;

	printk("console evtchn: %d\n", HA_xencons_evtchn);

	/* In case we have in-flight data after save/restore... */
	notify_daemon();

	return 0;
}

static void __xencons_resume(void)
{
	/* resume printk */
	resume_console();
}

void xencons_resume(void)
{
	__xencons_resume();
	(void)xencons_ring_init();
}

void xencons_fast_resume(void)
{
	__xencons_resume();
}

void xencons_suspend(void)
{
	struct xencons_interface *intf = xencons_interface();

	/* suspend printk */
	suspend_console();

	/* wait all data is handled by xenconsoled */
	wait_event(xencons_suspend_queue, intf->out_cons == intf->out_prod);
}
