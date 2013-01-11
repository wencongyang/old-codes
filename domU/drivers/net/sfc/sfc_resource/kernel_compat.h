/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides compatibility layer for various Linux kernel versions
 * (starting from 2.6.9 RHEL kernel).
 *
 * Copyright 2005-2010: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
 *
 * Certain parts of the driver were implemented by
 *          Alexandra Kossovsky <Alexandra.Kossovsky@oktetlabs.ru>
 *          OKTET Labs Ltd, Russia,
 *          http://oktetlabs.ru, <info@oktetlabs.ru>
 *          by request of Solarflare Communications
 *
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 ****************************************************************************
 */

#ifndef DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H
#define DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H

#include <linux/version.h>
#include <linux/moduleparam.h>
#include <linux/sched.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,16)
#include <linux/io.h>
#else
#include <asm/io.h>
#endif
#include <linux/pci.h>

/********* wait_for_completion_timeout() ********************/

/* RHEL_RELEASE_CODE from linux/version.h is only defined for 2.6.9-55EL
 * UTS_RELEASE is unfortunately unusable
 * Really only need this fix for <2.6.9-34EL
 */
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,11)) && \
	!defined(RHEL_RELEASE_CODE)

static inline unsigned long fastcall
efrm_wait_for_completion_timeout(struct completion *x, unsigned long timeout)
{
	might_sleep();

	spin_lock_irq(&x->wait.lock);
	if (!x->done) {
		DECLARE_WAITQUEUE(wait, current);

		wait.flags |= WQ_FLAG_EXCLUSIVE;
		__add_wait_queue_tail(&x->wait, &wait);
		do {
			__set_current_state(TASK_UNINTERRUPTIBLE);
			spin_unlock_irq(&x->wait.lock);
			timeout = schedule_timeout(timeout);
			spin_lock_irq(&x->wait.lock);
			if (!timeout) {
				__remove_wait_queue(&x->wait, &wait);
				goto out;
			}
		} while (!x->done);
		__remove_wait_queue(&x->wait, &wait);
	}
	x->done--;
out:
	spin_unlock_irq(&x->wait.lock);
	return timeout;
}

#  ifdef wait_for_completion_timeout
#    undef wait_for_completion_timeout
#  endif
#  define wait_for_completion_timeout efrm_wait_for_completion_timeout

#endif

/********* io mapping ********************/

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,9)

  #ifndef __iomem
  #define __iomem
  #endif

  static inline void efrm_iounmap(volatile void __iomem *addr)
  {
	  iounmap((void __iomem *)addr);
  }
  #define iounmap(arg) efrm_iounmap(arg)

#endif


/********* Memory allocation *************/

#ifndef IN_KERNEL_COMPAT_C
#  ifndef __GFP_COMP
#    define __GFP_COMP 0
#  endif
#  ifndef __GFP_ZERO
#    define __GFP_ZERO 0
#  endif
#endif


/********* pci_map_*() ********************/

extern void *efrm_dma_alloc_coherent(struct device *dev, size_t size,
				     dma_addr_t *dma_addr, int flag);

extern void efrm_dma_free_coherent(struct device *dev, size_t size,
				   void *ptr, dma_addr_t dma_addr);


#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,8))
static inline void efrm_pci_disable_msi(struct pci_dev *dev) {}
#undef pci_disable_msi
#define pci_disable_msi efrm_pci_disable_msi
#endif

#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
enum {
	false = 0,
	true = 1
};

typedef _Bool bool;
#endif /* LINUX_VERSION_CODE < 2.6.19 */

#endif /* DRIVER_LINUX_RESOURCE_KERNEL_COMPAT_H */

