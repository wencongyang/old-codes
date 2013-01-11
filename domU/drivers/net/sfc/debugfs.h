/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2008 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DEBUGFS_H
#define EFX_DEBUGFS_H

static inline int efx_init_debugfs_netdev(struct net_device *net_dev)
{
	return 0;
}
static inline void efx_fini_debugfs_netdev(struct net_device *net_dev) {}
static inline int efx_init_debugfs_port(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_port(struct efx_nic *efx) {}
static inline int efx_init_debugfs_nic(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_nic(struct efx_nic *efx) {}
static inline int efx_init_debugfs_channels(struct efx_nic *efx)
{
	return 0;
}
static inline void efx_fini_debugfs_channels(struct efx_nic *efx) {}
static inline int efx_init_debugfs(void)
{
	return 0;
}
static inline void efx_fini_debugfs(void) {}

#endif /* EFX_DEBUGFS_H */
