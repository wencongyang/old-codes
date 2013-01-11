/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides helpers to turn bit shifts into dword shifts and
 * check that the bit fields haven't overflown the dword etc.
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

#ifndef __EFRM_NIC_H__
#define __EFRM_NIC_H__

#include <ci/efhw/efhw_types.h>


struct efrm_nic_per_vi {
	unsigned long state;
	struct vi_resource *vi;
};


struct efrm_nic {
	struct efhw_nic efhw_nic;
	struct list_head link;
	struct list_head clients;
	struct efrm_nic_per_vi *vis;
};


#define efrm_nic(_efhw_nic)				\
  container_of(_efhw_nic, struct efrm_nic, efhw_nic)



#endif  /* __EFRM_NIC_H__ */
