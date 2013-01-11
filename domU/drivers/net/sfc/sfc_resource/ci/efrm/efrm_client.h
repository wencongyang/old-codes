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

#ifndef __EFRM_CLIENT_H__
#define __EFRM_CLIENT_H__


struct efrm_client;


struct efrm_client_callbacks {
	/* Called before device is reset.  Callee may block. */
	void (*pre_reset)(struct efrm_client *, void *user_data);
	void (*stop)(struct efrm_client *, void *user_data);
	void (*restart)(struct efrm_client *, void *user_data);
};


#define EFRM_IFINDEX_DEFAULT  -1


/* NB. Callbacks may be invoked even before this returns. */
extern int  efrm_client_get(int ifindex, struct efrm_client_callbacks *,
			    void *user_data, struct efrm_client **client_out);
extern void efrm_client_put(struct efrm_client *);

extern struct efhw_nic *efrm_client_get_nic(struct efrm_client *);
extern int efrm_client_get_ifindex(struct efrm_client *);

#if 0
/* For each resource type... */
extern void efrm_x_resource_resume(struct x_resource *);
#endif


#endif  /* __EFRM_CLIENT_H__ */
