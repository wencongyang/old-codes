/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005      Fen Systems Ltd.
 * Copyright 2006-2008 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_DRIVERLINK_H
#define EFX_DRIVERLINK_H

/* Forward declarations */
struct efx_dl_device;
struct efx_nic;

/* Efx callback devices
 *
 * A list of the devices that own each callback. The partner to
 * struct efx_dl_callbacks.
 */
struct efx_dl_cb_devices {
	struct efx_dl_device *tx_packet;
	struct efx_dl_device *rx_packet;
	struct efx_dl_device *request_mtu;
	struct efx_dl_device *mtu_changed;
	struct efx_dl_device *event;
};

extern struct efx_dl_callbacks efx_default_callbacks;

#define EFX_DL_CALLBACK(_port, _name, ...)				\
	(_port)->dl_cb._name((_port)->dl_cb_dev._name, __VA_ARGS__)

extern void efx_dl_register_nic(struct efx_nic *efx);
extern void efx_dl_unregister_nic(struct efx_nic *efx);

/* Suspend and resume client drivers over a hardware reset */
extern void efx_dl_reset_suspend(struct efx_nic *efx);
extern void efx_dl_reset_resume(struct efx_nic *efx, int ok);

/* Obtain the Efx NIC for the given driverlink device. */
extern struct efx_nic *efx_dl_get_nic(struct efx_dl_device *efx_dev);

#endif /* EFX_DRIVERLINK_H */
