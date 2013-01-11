/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file contains EtherFabric Generic NIC instance (init, interrupts,
 * etc)
 *
 * Copyright 2005-2010: Solarflare Communications Inc,
 *                      9501 Jeronimo Road, Suite 250,
 *                      Irvine, CA 92618, USA
 *
 * Developed and maintained by Solarflare Communications:
 *                      <linux-xen-drivers@solarflare.com>
 *                      <onload-dev@solarflare.com>
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

#include <ci/efhw/debug.h>
#include <ci/driver/efab/hardware.h>
#include <ci/efhw/falcon.h>
#include <ci/efhw/nic.h>
#include <ci/efhw/eventq.h>

/* Return 0 if not a known type */
int efhw_device_type_init(struct efhw_device_type *dt,
			  int vendor_id, int device_id,
			  int class_revision)
{
	if (vendor_id != 0x1924)
		return 0;

	memset(dt, 0, sizeof(*dt));
	
	switch (device_id) {
	case 0x0703:
	case 0x6703:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'A';
		switch (class_revision) {
		case 0:
			dt->revision = 0;
			break;
		case 1:
			dt->revision = 1;
			break;
		default:
			return 0;
		}
		break;
	case 0x0710:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'B';
		switch (class_revision) {
		case 2:
			dt->revision = 0;
			break;
		default:
			return 0;
		}
		break;
	/* Development */
	case 0x0770:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		dt->in_fpga = 1;
		break;
	case 0x7777:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		dt->in_fpga = 1;
		switch (class_revision) {
		case 0:
			dt->revision = 0;
			break;
		default:
			return 0;
		}
		break;
	/* cosim */
	case 0x7778:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		dt->in_cosim = 1;
		dt->revision = 0;
		if (class_revision > 0xf)
			return 0;
		break;
	case 0x0803:
		dt->arch = EFHW_ARCH_FALCON;
		dt->variant = 'C';
		switch (class_revision) {
		case 0: /* ASIC */
			dt->revision = 0;
			dt->in_fpga = 0;
			break;

		case 1:
		case 2: /* 20/Oct/08 indicates DBI has been alt initialized */
                case 3: /* 30/Sep/08 indicates DBI has been initialized */
			dt->revision = 0;
			dt->in_fpga = 1;
			break;

		default:
			return 0;
		}
		break;
	default:
		return 0;
	}

	return 1;
}


/*--------------------------------------------------------------------
 *
 * NIC Initialisation
 *
 *--------------------------------------------------------------------*/

/* make this separate from initialising data structure
** to allow this to be called at a later time once we can access PCI
** config space to find out what hardware we have
*/
void efhw_nic_init(struct efhw_nic *nic, unsigned flags, unsigned options,
		   struct efhw_device_type dev_type)
{
	nic->devtype = dev_type;
	nic->flags = flags;
	nic->options = options;
	nic->bar_ioaddr = 0;
	spin_lock_init(&nic->the_reg_lock);
	nic->reg_lock = &nic->the_reg_lock;
	nic->mtu = 1500 + ETH_HLEN;

	nic->irq_unit = EFHW_IRQ_UNIT_UNUSED;

	switch (nic->devtype.arch) {
	case EFHW_ARCH_FALCON:
		nic->evq_sizes = 512 | 1024 | 2048 | 4096 | 8192 |
			16384 | 32768;
		nic->txq_sizes = 512 | 1024 | 2048 | 4096;
		nic->rxq_sizes = 512 | 1024 | 2048 | 4096;
		nic->efhw_func = &falcon_char_functional_units;
		nic->ctr_ap_bytes = EFHW_64M;
		switch (nic->devtype.variant) {
		case 'A':
			nic->ctr_ap_bar = FALCON_S_CTR_AP_BAR;
			nic->num_evqs   = 4096;
			nic->num_dmaqs  = 4096;
			nic->num_timers = 4096;
			break;
		case 'B':
			nic->flags |= NIC_FLAG_NO_INTERRUPT;
			nic->ctr_ap_bar = FALCON_P_CTR_AP_BAR;
			nic->num_evqs   = 4096;
			nic->num_dmaqs  = 4096;
			nic->num_timers = 4096;
			break;
		case 'C':
			nic->flags |= NIC_FLAG_NO_INTERRUPT;
			nic->ctr_ap_bar = FALCON_P_CTR_AP_BAR;
			nic->num_evqs   = 1024;
			nic->num_dmaqs  = 1024;
			nic->num_timers = 1024;
			nic->ctr_ap_bytes = EFHW_16M;
			break;
		default:
			EFHW_ASSERT(0);
			break;
		}
		break;
	default:
		EFHW_ASSERT(0);
		break;
	}
}


void efhw_nic_close_interrupts(struct efhw_nic *nic)
{
	EFHW_ASSERT(nic);
	if (!efhw_nic_have_hw(nic))
		return;

	EFHW_ASSERT(efhw_nic_have_hw(nic));

	if (nic->irq_unit != EFHW_IRQ_UNIT_UNUSED)
		efhw_nic_interrupt_disable(nic);
}

void efhw_nic_dtor(struct efhw_nic *nic)
{
	EFHW_ASSERT(nic);

	/* Check that we have functional units because the software only
	 * driver doesn't initialise anything hardware related any more */

#ifndef __ci_ul_driver__
	/* close interrupts is called first because the act of deregistering
	   the driver could cause this driver to change from master to slave
	   and hence the implicit interrupt mappings would be wrong */

	EFHW_TRACE("%s: functional units ... ", __FUNCTION__);

	if (efhw_nic_have_functional_units(nic)) {
		efhw_nic_close_interrupts(nic);
		efhw_nic_close_hardware(nic);
	}
	EFHW_TRACE("%s: functional units ... done", __FUNCTION__);
#endif

	/* destroy event queues */
	EFHW_TRACE("%s: event queues ... ", __FUNCTION__);

#ifndef __ci_ul_driver__
	if (nic->interrupting_evq.evq_mask)
		efhw_keventq_dtor(nic, &nic->interrupting_evq);
	if (nic->non_interrupting_evq.evq_mask)
		efhw_keventq_dtor(nic, &nic->non_interrupting_evq);
#endif

	EFHW_TRACE("%s: event queues ... done", __FUNCTION__);

	spin_lock_destroy(&nic->the_reg_lock);

	EFHW_TRACE("%s: DONE", __FUNCTION__);
}
