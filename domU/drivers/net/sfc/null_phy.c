/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2006-2009 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include "efx.h"
#include "nic.h"
#include "phy.h"

static int falcon_null_phy_probe(struct efx_nic *efx)
{
	efx->mdio.mmds = 0;
	efx->mdio.mode_support = MDIO_SUPPORTS_C45 | MDIO_EMULATE_C22;

	efx->loopback_modes = FALCON_XMAC_LOOPBACKS;
	efx->startup_loopback_mode = LOOPBACK_XGMII;

	strlcpy(efx->phy_name, "none", sizeof(efx->phy_name));

	return 0;
}

static bool falcon_null_phy_poll(struct efx_nic *efx)
{
	bool was_up = efx->link_state.up;

	efx->link_state.speed = 10000;
	efx->link_state.fd = true;
	efx->link_state.fc = efx->wanted_fc;
	efx->link_state.up = !efx->xmac_poll_required;

	return efx->link_state.up != was_up;
}

static void falcon_null_phy_get_settings(struct efx_nic *efx,
					 struct ethtool_cmd *ecmd)
{
	struct efx_link_state *link_state = &efx->link_state;

	/* There is no port type for this so we fudge it as fibre. */
	ecmd->transceiver = XCVR_INTERNAL;
	ecmd->phy_address = MDIO_PRTAD_NONE;
	ecmd->supported = SUPPORTED_FIBRE;
	ecmd->advertising = ADVERTISED_FIBRE;
	ecmd->port = PORT_FIBRE;
	ecmd->autoneg = AUTONEG_DISABLE;

	ecmd->duplex = link_state->fd;
	ecmd->speed = link_state->speed;
}

static int falcon_null_phy_set_settings(struct efx_nic *efx,
					struct ethtool_cmd *ecmd)
{
	struct efx_link_state *link_state = &efx->link_state;

	switch (ecmd->speed) {
	case 10:
	case 100:
	case 1000:
		/* TODO: verify PCS mode */
		if (efx_nic_rev(efx) < EFX_REV_SIENA_A0)
			return -EOPNOTSUPP;
		/* fall through */
	case 10000:
		link_state->speed = ecmd->speed;
		break;
	default:
		return -EOPNOTSUPP;
	}

	if (ecmd->transceiver != XCVR_INTERNAL ||
	    ecmd->phy_address != (u8)MDIO_PRTAD_NONE ||
	    ecmd->supported != SUPPORTED_FIBRE ||
	    ecmd->advertising != ADVERTISED_FIBRE ||
	    ecmd->duplex != DUPLEX_FULL ||
	    ecmd->port != PORT_FIBRE ||
	    ecmd->autoneg != AUTONEG_DISABLE)
		return -EOPNOTSUPP;
	return 0;
}

struct efx_phy_operations falcon_null_phy_ops = {
	.probe		= falcon_null_phy_probe,
	.init	 	= efx_port_dummy_op_int,
	.reconfigure	= efx_port_dummy_op_int,
	.poll	 	= falcon_null_phy_poll,
	.fini		= efx_port_dummy_op_void,
	.remove		= efx_port_dummy_op_void,
	.get_settings	= falcon_null_phy_get_settings,
	.set_settings	= falcon_null_phy_set_settings,
};
