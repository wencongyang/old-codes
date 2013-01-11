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

#ifndef __EFRM_INTERNAL_H__
#define __EFRM_INTERNAL_H__


struct filter_resource {
	struct efrm_resource rs;
	struct vi_resource *pt;
	int filter_idx;
};

#define filter_resource(rs1)  container_of((rs1), struct filter_resource, rs)


struct efrm_client {
	void *user_data;
	struct list_head link;
	struct efrm_client_callbacks *callbacks;
	struct efhw_nic *nic;
	int ref_count;
	struct list_head resources;
};


extern void efrm_client_add_resource(struct efrm_client *,
				     struct efrm_resource *);

extern int efrm_buffer_table_size(void);


static inline void efrm_resource_init(struct efrm_resource *rs,
				      int type, int instance)
{
	EFRM_ASSERT(instance >= 0);
	EFRM_ASSERT(type >= 0 && type < EFRM_RESOURCE_NUM);
	rs->rs_ref_count = 1;
	rs->rs_handle.handle = (type << 28u) |
		(((unsigned)jiffies & 0xfff) << 16) | instance;
}


#endif  /* __EFRM_INTERNAL_H__ */
