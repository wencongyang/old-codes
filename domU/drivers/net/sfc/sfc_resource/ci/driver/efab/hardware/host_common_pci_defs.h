/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides EtherFabric NIC hardware interface common
 * definitions.
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

#ifndef	PCI_PROGMODEL_DEFS_H
#define	PCI_PROGMODEL_DEFS_H

/*------------------------------------------------------------*/
/*
 * PCR_AZ_PM_CS_REG(16bit):
 * Power management control & status register
 */
#define	PCR_AZ_PM_CS_REG 0x00000044
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_PM_PME_STAT_LBN 15
#define	PCRF_AZ_PM_PME_STAT_WIDTH 1
#define	PCRF_AZ_PM_DAT_SCALE_LBN 13
#define	PCRF_AZ_PM_DAT_SCALE_WIDTH 2
#define	PCRF_AZ_PM_DAT_SEL_LBN 9
#define	PCRF_AZ_PM_DAT_SEL_WIDTH 4
#define	PCRF_AZ_PM_PME_EN_LBN 8
#define	PCRF_AZ_PM_PME_EN_WIDTH 1
#define	PCRF_CZ_NO_SOFT_RESET_LBN 3
#define	PCRF_CZ_NO_SOFT_RESET_WIDTH 1
#define	PCRF_AZ_PM_PWR_ST_LBN 0
#define	PCRF_AZ_PM_PWR_ST_WIDTH 2


/*------------------------------------------------------------*/
/*
 * PCR_AZ_VEND_ID_REG(16bit):
 * Vendor ID register
 */
#define	PCR_AZ_VEND_ID_REG 0x00000000
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_VEND_ID_LBN 0
#define	PCRF_AZ_VEND_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_DEV_ID_REG(16bit):
 * Device ID register
 */
#define	PCR_AZ_DEV_ID_REG 0x00000002
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_DEV_ID_LBN 0
#define	PCRF_AZ_DEV_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_REV_ID_REG(8bit):
 * Class code & revision ID register
 */
#define	PCR_AZ_REV_ID_REG 0x00000008
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_REV_ID_LBN 0
#define	PCRF_AZ_REV_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_CC_REG(24bit):
 * Class code register
 */
#define	PCR_AZ_CC_REG 0x00000009
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_BASE_CC_LBN 16
#define	PCRF_AZ_BASE_CC_WIDTH 8
#define	PCRF_AZ_SUB_CC_LBN 8
#define	PCRF_AZ_SUB_CC_WIDTH 8
#define	PCRF_AZ_PROG_IF_LBN 0
#define	PCRF_AZ_PROG_IF_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MST_LAT_REG(8bit):
 * Master latency timer register
 */
#define	PCR_AZ_MST_LAT_REG 0x0000000d
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_MST_LAT_LBN 0
#define	PCRF_AZ_MST_LAT_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_HDR_TYPE_REG(8bit):
 * Header type register
 */
#define	PCR_AZ_HDR_TYPE_REG 0x0000000e
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_MULT_FUNC_LBN 7
#define	PCRF_AZ_MULT_FUNC_WIDTH 1
#define	PCRF_AZ_TYPE_LBN 0
#define	PCRF_AZ_TYPE_WIDTH 7


/*------------------------------------------------------------*/
/*
 * PCR_AZ_BIST_REG(8bit):
 * BIST register
 */
#define	PCR_AZ_BIST_REG 0x0000000f
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_BIST_LBN 0
#define	PCRF_AZ_BIST_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_BAR4_LO_REG(32bit):
 * Primary function base address register 2 low bits
 */
#define	PCR_CZ_BAR4_LO_REG 0x00000020
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_BAR4_LO_LBN 4
#define	PCRF_CZ_BAR4_LO_WIDTH 28
#define	PCRF_CZ_BAR4_PREF_LBN 3
#define	PCRF_CZ_BAR4_PREF_WIDTH 1
#define	PCRF_CZ_BAR4_TYPE_LBN 1
#define	PCRF_CZ_BAR4_TYPE_WIDTH 2
#define	PCRF_CZ_BAR4_IOM_LBN 0
#define	PCRF_CZ_BAR4_IOM_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_SS_ID_REG(16bit):
 * Sub-system ID register
 */
#define	PCR_AZ_SS_ID_REG 0x0000002e
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_SS_ID_LBN 0
#define	PCRF_AZ_SS_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_EXPROM_BAR_REG(32bit):
 * Expansion ROM base address register
 */
#define	PCR_AZ_EXPROM_BAR_REG 0x00000030
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_EXPROM_BAR_LBN 11
#define	PCRF_AZ_EXPROM_BAR_WIDTH 21
#define	PCRF_AB_EXPROM_MIN_SIZE_LBN 2
#define	PCRF_AB_EXPROM_MIN_SIZE_WIDTH 9
#define	PCRF_CZ_EXPROM_MIN_SIZE_LBN 1
#define	PCRF_CZ_EXPROM_MIN_SIZE_WIDTH 10
#define	PCRF_AB_EXPROM_FEATURE_ENABLE_LBN 1
#define	PCRF_AB_EXPROM_FEATURE_ENABLE_WIDTH 1
#define	PCRF_AZ_EXPROM_EN_LBN 0
#define	PCRF_AZ_EXPROM_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_CAP_PTR_REG(8bit):
 * Capability pointer register
 */
#define	PCR_AZ_CAP_PTR_REG 0x00000034
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_CAP_PTR_LBN 0
#define	PCRF_AZ_CAP_PTR_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_INT_LINE_REG(8bit):
 * Interrupt line register
 */
#define	PCR_AZ_INT_LINE_REG 0x0000003c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_INT_LINE_LBN 0
#define	PCRF_AZ_INT_LINE_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_INT_PIN_REG(8bit):
 * Interrupt pin register
 */
#define	PCR_AZ_INT_PIN_REG 0x0000003d
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_INT_PIN_LBN 0
#define	PCRF_AZ_INT_PIN_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MSI_CAP_ID_REG(8bit):
 * MSI capability ID
 */
#define	PCR_AZ_MSI_CAP_ID_REG 0x00000050
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_MSI_CAP_ID_LBN 0
#define	PCRF_AZ_MSI_CAP_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MSI_NXT_PTR_REG(8bit):
 * MSI next item pointer
 */
#define	PCR_AZ_MSI_NXT_PTR_REG 0x00000051
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_MSI_NXT_PTR_LBN 0
#define	PCRF_AZ_MSI_NXT_PTR_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MSI_CTL_REG(16bit):
 * MSI control register
 */
#define	PCR_AZ_MSI_CTL_REG 0x00000052
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_MSI_64_EN_LBN 7
#define	PCRF_AZ_MSI_64_EN_WIDTH 1
#define	PCRF_AZ_MSI_MULT_MSG_EN_LBN 4
#define	PCRF_AZ_MSI_MULT_MSG_EN_WIDTH 3
#define	PCRF_AZ_MSI_MULT_MSG_CAP_LBN 1
#define	PCRF_AZ_MSI_MULT_MSG_CAP_WIDTH 3
#define	PCRF_AZ_MSI_EN_LBN 0
#define	PCRF_AZ_MSI_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MSI_ADR_HI_REG(32bit):
 * MSI high 32 bits address register
 */
#define	PCR_AZ_MSI_ADR_HI_REG 0x00000058
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_MSI_ADR_HI_LBN 0
#define	PCRF_AZ_MSI_ADR_HI_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_CZ_PCIE_CAP_LIST_REG(16bit):
 * PCIe capability list register
 */
#define	PCR_CZ_PCIE_CAP_LIST_REG 0x00000070
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_PCIE_CAP_LIST_REG(16bit):
 * PCIe capability list register
 */
#define	PCR_AB_PCIE_CAP_LIST_REG 0x00000060
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_PCIE_NXT_PTR_LBN 8
#define	PCRF_AZ_PCIE_NXT_PTR_WIDTH 8
#define	PCRF_AZ_PCIE_CAP_ID_LBN 0
#define	PCRF_AZ_PCIE_CAP_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEV_CAP_REG(28bit):
 * PCIe device capabilities register
 */
#define	PCR_CZ_DEV_CAP_REG 0x00000074
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_DEV_CAP_REG(28bit):
 * PCIe device capabilities register
 */
#define	PCR_AB_DEV_CAP_REG 0x00000064
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_CZ_CAP_FN_LEVEL_RESET_LBN 28
#define	PCRF_CZ_CAP_FN_LEVEL_RESET_WIDTH 1
#define	PCRF_AZ_CAP_SLOT_PWR_SCL_LBN 26
#define	PCRF_AZ_CAP_SLOT_PWR_SCL_WIDTH 2
#define	PCRF_AZ_CAP_SLOT_PWR_VAL_LBN 18
#define	PCRF_AZ_CAP_SLOT_PWR_VAL_WIDTH 8
#define	PCRF_CZ_ROLE_BASE_ERR_REPORTING_LBN 15
#define	PCRF_CZ_ROLE_BASE_ERR_REPORTING_WIDTH 1
#define	PCRF_AB_PWR_IND_LBN 14
#define	PCRF_AB_PWR_IND_WIDTH 1
#define	PCRF_AB_ATTN_IND_LBN 13
#define	PCRF_AB_ATTN_IND_WIDTH 1
#define	PCRF_AB_ATTN_BUTTON_LBN 12
#define	PCRF_AB_ATTN_BUTTON_WIDTH 1
#define	PCRF_AZ_ENDPT_L1_LAT_LBN 9
#define	PCRF_AZ_ENDPT_L1_LAT_WIDTH 3
#define	PCRF_AZ_ENDPT_L0_LAT_LBN 6
#define	PCRF_AZ_ENDPT_L0_LAT_WIDTH 3
#define	PCRF_AZ_TAG_FIELD_LBN 5
#define	PCRF_AZ_TAG_FIELD_WIDTH 1
#define	PCRF_AZ_PHAN_FUNC_LBN 3
#define	PCRF_AZ_PHAN_FUNC_WIDTH 2
#define	PCRF_AZ_MAX_PAYL_SIZE_SUPT_LBN 0
#define	PCRF_AZ_MAX_PAYL_SIZE_SUPT_WIDTH 3


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEV_CTL_REG(16bit):
 * PCIe device control register
 */
#define	PCR_CZ_DEV_CTL_REG 0x00000078
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_DEV_CTL_REG(16bit):
 * PCIe device control register
 */
#define	PCR_AB_DEV_CTL_REG 0x00000068
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_CZ_FN_LEVEL_RESET_LBN 15
#define	PCRF_CZ_FN_LEVEL_RESET_WIDTH 1
#define	PCRF_AZ_MAX_RD_REQ_SIZE_LBN 12
#define	PCRF_AZ_MAX_RD_REQ_SIZE_WIDTH 3
#define	PCFE_AZ_MAX_RD_REQ_SIZE_4096 5
#define	PCFE_AZ_MAX_RD_REQ_SIZE_2048 4
#define	PCFE_AZ_MAX_RD_REQ_SIZE_1024 3
#define	PCFE_AZ_MAX_RD_REQ_SIZE_512 2
#define	PCFE_AZ_MAX_RD_REQ_SIZE_256 1
#define	PCFE_AZ_MAX_RD_REQ_SIZE_128 0
#define	PCRF_AZ_EN_NO_SNOOP_LBN 11
#define	PCRF_AZ_EN_NO_SNOOP_WIDTH 1
#define	PCRF_AZ_AUX_PWR_PM_EN_LBN 10
#define	PCRF_AZ_AUX_PWR_PM_EN_WIDTH 1
#define	PCRF_AZ_PHAN_FUNC_EN_LBN 9
#define	PCRF_AZ_PHAN_FUNC_EN_WIDTH 1
#define	PCRF_AB_DEV_CAP_REG_RSVD0_LBN 8
#define	PCRF_AB_DEV_CAP_REG_RSVD0_WIDTH 1
#define	PCRF_CZ_EXTENDED_TAG_EN_LBN 8
#define	PCRF_CZ_EXTENDED_TAG_EN_WIDTH 1
#define	PCRF_AZ_MAX_PAYL_SIZE_LBN 5
#define	PCRF_AZ_MAX_PAYL_SIZE_WIDTH 3
#define	PCFE_AZ_MAX_PAYL_SIZE_4096 5
#define	PCFE_AZ_MAX_PAYL_SIZE_2048 4
#define	PCFE_AZ_MAX_PAYL_SIZE_1024 3
#define	PCFE_AZ_MAX_PAYL_SIZE_512 2
#define	PCFE_AZ_MAX_PAYL_SIZE_256 1
#define	PCFE_AZ_MAX_PAYL_SIZE_128 0
#define	PCRF_AZ_EN_RELAX_ORDER_LBN 4
#define	PCRF_AZ_EN_RELAX_ORDER_WIDTH 1
#define	PCRF_AZ_UNSUP_REQ_RPT_EN_LBN 3
#define	PCRF_AZ_UNSUP_REQ_RPT_EN_WIDTH 1
#define	PCRF_AZ_FATAL_ERR_RPT_EN_LBN 2
#define	PCRF_AZ_FATAL_ERR_RPT_EN_WIDTH 1
#define	PCRF_AZ_NONFATAL_ERR_RPT_EN_LBN 1
#define	PCRF_AZ_NONFATAL_ERR_RPT_EN_WIDTH 1
#define	PCRF_AZ_CORR_ERR_RPT_EN_LBN 0
#define	PCRF_AZ_CORR_ERR_RPT_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEV_STAT_REG(16bit):
 * PCIe device status register
 */
#define	PCR_CZ_DEV_STAT_REG 0x0000007a
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_DEV_STAT_REG(16bit):
 * PCIe device status register
 */
#define	PCR_AB_DEV_STAT_REG 0x0000006a
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_TRNS_PEND_LBN 5
#define	PCRF_AZ_TRNS_PEND_WIDTH 1
#define	PCRF_AZ_AUX_PWR_DET_LBN 4
#define	PCRF_AZ_AUX_PWR_DET_WIDTH 1
#define	PCRF_AZ_UNSUP_REQ_DET_LBN 3
#define	PCRF_AZ_UNSUP_REQ_DET_WIDTH 1
#define	PCRF_AZ_FATAL_ERR_DET_LBN 2
#define	PCRF_AZ_FATAL_ERR_DET_WIDTH 1
#define	PCRF_AZ_NONFATAL_ERR_DET_LBN 1
#define	PCRF_AZ_NONFATAL_ERR_DET_WIDTH 1
#define	PCRF_AZ_CORR_ERR_DET_LBN 0
#define	PCRF_AZ_CORR_ERR_DET_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_LNK_CAP_REG(32bit):
 * PCIe link capabilities register
 */
#define	PCR_CZ_LNK_CAP_REG 0x0000007c
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_LNK_CAP_REG(32bit):
 * PCIe link capabilities register
 */
#define	PCR_AB_LNK_CAP_REG 0x0000006c
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_PORT_NUM_LBN 24
#define	PCRF_AZ_PORT_NUM_WIDTH 8
#define	PCRF_CZ_LINK_BWDITH_NOTIF_CAP_LBN 21
#define	PCRF_CZ_LINK_BWDITH_NOTIF_CAP_WIDTH 1
#define	PCRF_CZ_DATA_LINK_ACTIVE_RPT_CAP_LBN 20
#define	PCRF_CZ_DATA_LINK_ACTIVE_RPT_CAP_WIDTH 1
#define	PCRF_CZ_SURPISE_DOWN_RPT_CAP_LBN 19
#define	PCRF_CZ_SURPISE_DOWN_RPT_CAP_WIDTH 1
#define	PCRF_CZ_CLOCK_PWR_MNGMNT_CAP_LBN 18
#define	PCRF_CZ_CLOCK_PWR_MNGMNT_CAP_WIDTH 1
#define	PCRF_AZ_DEF_L1_EXIT_LAT_LBN 15
#define	PCRF_AZ_DEF_L1_EXIT_LAT_WIDTH 3
#define	PCRF_AZ_DEF_L0_EXIT_LATPORT_NUM_LBN 12
#define	PCRF_AZ_DEF_L0_EXIT_LATPORT_NUM_WIDTH 3
#define	PCRF_AZ_AS_LNK_PM_SUPT_LBN 10
#define	PCRF_AZ_AS_LNK_PM_SUPT_WIDTH 2
#define	PCRF_AZ_MAX_LNK_WIDTH_LBN 4
#define	PCRF_AZ_MAX_LNK_WIDTH_WIDTH 6
#define	PCRF_AZ_MAX_LNK_SP_LBN 0
#define	PCRF_AZ_MAX_LNK_SP_WIDTH 4


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEV_CTL2_REG(16bit):
 * PCIe Device Control 2
 */
#define	PCR_CZ_DEV_CTL2_REG 0x00000098
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_CMPL_TIMEOUT_DIS_CTL_LBN 4
#define	PCRF_CZ_CMPL_TIMEOUT_DIS_CTL_WIDTH 1
#define	PCRF_CZ_CMPL_TIMEOUT_CTL_LBN 0
#define	PCRF_CZ_CMPL_TIMEOUT_CTL_WIDTH 4


/*------------------------------------------------------------*/
/*
 * PCR_CZ_LNK_STAT2_REG(16bit):
 * PCIe Link Status 2
 */
#define	PCR_CZ_LNK_STAT2_REG 0x000000a2
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_CURRENT_DEEMPH_LBN 0
#define	PCRF_CZ_CURRENT_DEEMPH_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_MSIX_NXT_PTR_REG(8bit):
 * MSIX Capability Next Capability Ptr
 */
#define	PCR_CZ_MSIX_NXT_PTR_REG 0x000000b1
/* sienaa0=pci_f0_config */
/*
 * PCR_BB_MSIX_NXT_PTR_REG(8bit):
 * MSIX Capability Next Capability Ptr
 */
#define	PCR_BB_MSIX_NXT_PTR_REG 0x00000091
/* falconb0=pci_f0_config */

#define	PCRF_BZ_MSIX_NXT_PTR_LBN 0
#define	PCRF_BZ_MSIX_NXT_PTR_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_MSIX_CTL_REG(16bit):
 * MSIX control register
 */
#define	PCR_CZ_MSIX_CTL_REG 0x000000b2
/* sienaa0=pci_f0_config */
/*
 * PCR_BB_MSIX_CTL_REG(16bit):
 * MSIX control register
 */
#define	PCR_BB_MSIX_CTL_REG 0x00000092
/* falconb0=pci_f0_config */

#define	PCRF_BZ_MSIX_EN_LBN 15
#define	PCRF_BZ_MSIX_EN_WIDTH 1
#define	PCRF_BZ_MSIX_FUNC_MASK_LBN 14
#define	PCRF_BZ_MSIX_FUNC_MASK_WIDTH 1
#define	PCRF_BZ_MSIX_TBL_SIZE_LBN 0
#define	PCRF_BZ_MSIX_TBL_SIZE_WIDTH 11


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_UNCORR_ERR_SEV_REG(32bit):
 * AER Uncorrectable error severity register
 */
#define	PCR_AZ_AER_UNCORR_ERR_SEV_REG 0x0000010c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_UNSUPT_REQ_ERR_SEV_LBN 20
#define	PCRF_AZ_UNSUPT_REQ_ERR_SEV_WIDTH 1
#define	PCRF_AZ_ECRC_ERR_SEV_LBN 19
#define	PCRF_AZ_ECRC_ERR_SEV_WIDTH 1
#define	PCRF_AZ_MALF_TLP_SEV_LBN 18
#define	PCRF_AZ_MALF_TLP_SEV_WIDTH 1
#define	PCRF_AZ_RX_OVF_SEV_LBN 17
#define	PCRF_AZ_RX_OVF_SEV_WIDTH 1
#define	PCRF_AZ_UNEXP_COMP_SEV_LBN 16
#define	PCRF_AZ_UNEXP_COMP_SEV_WIDTH 1
#define	PCRF_AZ_COMP_ABRT_SEV_LBN 15
#define	PCRF_AZ_COMP_ABRT_SEV_WIDTH 1
#define	PCRF_AZ_COMP_TIMEOUT_SEV_LBN 14
#define	PCRF_AZ_COMP_TIMEOUT_SEV_WIDTH 1
#define	PCRF_AZ_FC_PROTO_ERR_SEV_LBN 13
#define	PCRF_AZ_FC_PROTO_ERR_SEV_WIDTH 1
#define	PCRF_AZ_PSON_TLP_SEV_LBN 12
#define	PCRF_AZ_PSON_TLP_SEV_WIDTH 1
#define	PCRF_AZ_DL_PROTO_ERR_SEV_LBN 4
#define	PCRF_AZ_DL_PROTO_ERR_SEV_WIDTH 1
#define	PCRF_AB_TRAIN_ERR_SEV_LBN 0
#define	PCRF_AB_TRAIN_ERR_SEV_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_CORR_ERR_STAT_REG(32bit):
 * AER Correctable error status register
 */
#define	PCR_AZ_AER_CORR_ERR_STAT_REG 0x00000110
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_CZ_ADVSY_NON_FATAL_STAT_LBN 13
#define	PCRF_CZ_ADVSY_NON_FATAL_STAT_WIDTH 1
#define	PCRF_AZ_RPLY_TMR_TOUT_STAT_LBN 12
#define	PCRF_AZ_RPLY_TMR_TOUT_STAT_WIDTH 1
#define	PCRF_AZ_RPLAY_NUM_RO_STAT_LBN 8
#define	PCRF_AZ_RPLAY_NUM_RO_STAT_WIDTH 1
#define	PCRF_AZ_BAD_DLLP_STAT_LBN 7
#define	PCRF_AZ_BAD_DLLP_STAT_WIDTH 1
#define	PCRF_AZ_BAD_TLP_STAT_LBN 6
#define	PCRF_AZ_BAD_TLP_STAT_WIDTH 1
#define	PCRF_AZ_RX_ERR_STAT_LBN 0
#define	PCRF_AZ_RX_ERR_STAT_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEVSN_DWORD1_REG(32bit):
 * Device serial number DWORD0
 */
#define	PCR_CZ_DEVSN_DWORD1_REG 0x00000148
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_DEVSN_DWORD1_LBN 0
#define	PCRF_CZ_DEVSN_DWORD1_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_CZ_ARI_CTL_REG(16bit):
 * ARI Control
 */
#define	PCR_CZ_ARI_CTL_REG 0x00000156
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_ARI_FN_GRP_LBN 4
#define	PCRF_CZ_ARI_FN_GRP_WIDTH 3
#define	PCRF_CZ_ARI_ACS_FNGRP_EN_LBN 1
#define	PCRF_CZ_ARI_ACS_FNGRP_EN_WIDTH 1
#define	PCRF_CZ_ARI_MFVC_FNGRP_EN_LBN 0
#define	PCRF_CZ_ARI_MFVC_FNGRP_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_CAP_HDR_REG(32bit):
 * SRIOV capability header register
 */
#define	PCR_CZ_SRIOV_CAP_HDR_REG 0x00000160
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_SRIOVCAPHDR_NXT_PTR_LBN 20
#define	PCRF_CZ_SRIOVCAPHDR_NXT_PTR_WIDTH 12
#define	PCRF_CZ_SRIOVCAPHDR_VER_LBN 16
#define	PCRF_CZ_SRIOVCAPHDR_VER_WIDTH 4
#define	PCRF_CZ_SRIOVCAPHDR_ID_LBN 0
#define	PCRF_CZ_SRIOVCAPHDR_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_INITIALVFS_REG(16bit):
 * SRIOV Initial VFs
 */
#define	PCR_CZ_SRIOV_INITIALVFS_REG 0x0000016c
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_INITIALVFS_LBN 0
#define	PCRF_CZ_VF_INITIALVFS_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_FN_DPND_LNK_REG(16bit):
 * SRIOV Function dependency link
 */
#define	PCR_CZ_SRIOV_FN_DPND_LNK_REG 0x00000172
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_SRIOV_FN_DPND_LNK_LBN 0
#define	PCRF_CZ_SRIOV_FN_DPND_LNK_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_1STVF_OFFSET_REG(16bit):
 * SRIOV First VF Offset
 */
#define	PCR_CZ_SRIOV_1STVF_OFFSET_REG 0x00000174
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_1STVF_OFFSET_LBN 0
#define	PCRF_CZ_VF_1STVF_OFFSET_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_CMD_REG(16bit):
 * Command register
 */
#define	PCR_AZ_CMD_REG 0x00000004
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_INTX_DIS_LBN 10
#define	PCRF_AZ_INTX_DIS_WIDTH 1
#define	PCRF_AZ_FB2B_EN_LBN 9
#define	PCRF_AZ_FB2B_EN_WIDTH 1
#define	PCRF_AZ_SERR_EN_LBN 8
#define	PCRF_AZ_SERR_EN_WIDTH 1
#define	PCRF_AZ_IDSEL_CTL_LBN 7
#define	PCRF_AZ_IDSEL_CTL_WIDTH 1
#define	PCRF_AZ_PERR_EN_LBN 6
#define	PCRF_AZ_PERR_EN_WIDTH 1
#define	PCRF_AZ_VGA_PAL_SNP_LBN 5
#define	PCRF_AZ_VGA_PAL_SNP_WIDTH 1
#define	PCRF_AZ_MWI_EN_LBN 4
#define	PCRF_AZ_MWI_EN_WIDTH 1
#define	PCRF_AZ_SPEC_CYC_LBN 3
#define	PCRF_AZ_SPEC_CYC_WIDTH 1
#define	PCRF_AZ_MST_EN_LBN 2
#define	PCRF_AZ_MST_EN_WIDTH 1
#define	PCRF_AZ_MEM_EN_LBN 1
#define	PCRF_AZ_MEM_EN_WIDTH 1
#define	PCRF_AZ_IO_EN_LBN 0
#define	PCRF_AZ_IO_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AB_VPD_CAP_DATA_REG(32bit):
 * documentation to be written for sum_PC_VPD_CAP_DATA_REG
 */
#define	PCR_AB_VPD_CAP_DATA_REG 0x000000b4
/* falcona0,falconb0=pci_f0_config */
/*
 * PCR_CZ_VPD_CAP_DATA_REG(32bit):
 * documentation to be written for sum_PC_VPD_CAP_DATA_REG
 */
#define	PCR_CZ_VPD_CAP_DATA_REG 0x000000d4
/* sienaa0=pci_f0_config */

#define	PCRF_AZ_VPD_DATA_LBN 0
#define	PCRF_AZ_VPD_DATA_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_AZ_BAR2_HI_REG(32bit):
 * Primary function base address register 2 high bits
 */
#define	PCR_AZ_BAR2_HI_REG 0x0000001c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_BAR2_HI_LBN 0
#define	PCRF_AZ_BAR2_HI_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_AZ_SS_VEND_ID_REG(16bit):
 * Sub-system vendor ID register
 */
#define	PCR_AZ_SS_VEND_ID_REG 0x0000002c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_SS_VEND_ID_LBN 0
#define	PCRF_AZ_SS_VEND_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_CAP_HDR_REG(32bit):
 * AER capability header register
 */
#define	PCR_AZ_AER_CAP_HDR_REG 0x00000100
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_AERCAPHDR_NXT_PTR_LBN 20
#define	PCRF_AZ_AERCAPHDR_NXT_PTR_WIDTH 12
#define	PCRF_AZ_AERCAPHDR_VER_LBN 16
#define	PCRF_AZ_AERCAPHDR_VER_WIDTH 4
#define	PCRF_AZ_AERCAPHDR_ID_LBN 0
#define	PCRF_AZ_AERCAPHDR_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_HDR_LOG_REG(128bit):
 * AER Header log register
 */
#define	PCR_AZ_AER_HDR_LOG_REG 0x0000011c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_HDR_LOG_LBN 0
#define	PCRF_AZ_HDR_LOG_WIDTH 128


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_VFSTRIDE_REG(16bit):
 * SRIOV VF Stride
 */
#define	PCR_CZ_SRIOV_VFSTRIDE_REG 0x00000176
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_VFSTRIDE_LBN 0
#define	PCRF_CZ_VF_VFSTRIDE_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_DEVID_REG(16bit):
 * SRIOV VF Device ID
 */
#define	PCR_CZ_SRIOV_DEVID_REG 0x0000017a
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_DEVID_LBN 0
#define	PCRF_CZ_VF_DEVID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_SYS_PAGESZ_REG(32bit):
 * SRIOV System Page Size
 */
#define	PCR_CZ_SRIOV_SYS_PAGESZ_REG 0x00000180
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_SYS_PAGESZ_LBN 0
#define	PCRF_CZ_VF_SYS_PAGESZ_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_MIBR_SARRAY_OFFSET_REG(32bit):
 * SRIOV VF Migration State Array Offset
 */
#define	PCR_CZ_SRIOV_MIBR_SARRAY_OFFSET_REG 0x0000019c
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_MIGR_OFFSET_LBN 3
#define	PCRF_CZ_VF_MIGR_OFFSET_WIDTH 29
#define	PCRF_CZ_VF_MIGR_BIR_LBN 0
#define	PCRF_CZ_VF_MIGR_BIR_WIDTH 3


/*------------------------------------------------------------*/
/*
 * PCR_AZ_ACK_FREQ_REG(32bit):
 * ACK frequency register
 */
#define	PCR_AZ_ACK_FREQ_REG 0x0000070c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_CZ_ALLOW_L1_WITHOUT_L0S_LBN 30
#define	PCRF_CZ_ALLOW_L1_WITHOUT_L0S_WIDTH 1
#define	PCRF_AZ_L1_ENTR_LAT_LBN 27
#define	PCRF_AZ_L1_ENTR_LAT_WIDTH 3
#define	PCRF_AZ_L0_ENTR_LAT_LBN 24
#define	PCRF_AZ_L0_ENTR_LAT_WIDTH 3
#define	PCRF_CZ_COMM_NFTS_LBN 16
#define	PCRF_CZ_COMM_NFTS_WIDTH 8
#define	PCRF_AB_ACK_FREQ_REG_RSVD0_LBN 16
#define	PCRF_AB_ACK_FREQ_REG_RSVD0_WIDTH 3
#define	PCRF_AZ_MAX_FTS_LBN 8
#define	PCRF_AZ_MAX_FTS_WIDTH 8
#define	PCRF_AZ_ACK_FREQ_LBN 0
#define	PCRF_AZ_ACK_FREQ_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_DEBUG0_REG(32bit):
 * Debug register 0
 */
#define	PCR_AZ_DEBUG0_REG 0x00000728
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_CDI03_LBN 24
#define	PCRF_AZ_CDI03_WIDTH 8
#define	PCRF_AZ_CDI0_LBN 0
#define	PCRF_AZ_CDI0_WIDTH 32
#define	PCRF_AZ_CDI02_LBN 16
#define	PCRF_AZ_CDI02_WIDTH 8
#define	PCRF_AZ_CDI01_LBN 8
#define	PCRF_AZ_CDI01_WIDTH 8
#define	PCRF_AZ_CDI00_LBN 0
#define	PCRF_AZ_CDI00_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_VC_XMIT_ARB2_REG(32bit):
 * VC Transmit Arbitration Register 2
 */
#define	PCR_CZ_VC_XMIT_ARB2_REG 0x00000744
/* sienaa0=pci_f0_config */



/*------------------------------------------------------------*/
/*
 * PCR_AZ_CACHE_LSIZE_REG(8bit):
 * Cache line size
 */
#define	PCR_AZ_CACHE_LSIZE_REG 0x0000000c
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_CACHE_LSIZE_LBN 0
#define	PCRF_AZ_CACHE_LSIZE_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_PM_CAP_ID_REG(8bit):
 * Power management capability ID
 */
#define	PCR_AZ_PM_CAP_ID_REG 0x00000040
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_PM_CAP_ID_LBN 0
#define	PCRF_AZ_PM_CAP_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MSI_DAT_REG(16bit):
 * MSI data register
 */
#define	PCR_AZ_MSI_DAT_REG 0x0000005c
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_MSI_DAT_LBN 0
#define	PCRF_AZ_MSI_DAT_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_AZ_FORCE_LNK_REG(24bit):
 * Port force link register
 */
#define	PCR_AZ_FORCE_LNK_REG 0x00000708
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_LFS_LBN 16
#define	PCRF_AZ_LFS_WIDTH 6
#define	PCRF_AZ_FL_LBN 15
#define	PCRF_AZ_FL_WIDTH 1
#define	PCRF_AZ_LN_LBN 0
#define	PCRF_AZ_LN_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEV_CAP2_REG(16bit):
 * PCIe Device Capabilities 2
 */
#define	PCR_CZ_DEV_CAP2_REG 0x00000094
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_CMPL_TIMEOUT_DIS_LBN 4
#define	PCRF_CZ_CMPL_TIMEOUT_DIS_WIDTH 1
#define	PCRF_CZ_CMPL_TIMEOUT_LBN 0
#define	PCRF_CZ_CMPL_TIMEOUT_WIDTH 4
#define	PCFE_CZ_CMPL_TIMEOUT_17000_TO_6400MS 14
#define	PCFE_CZ_CMPL_TIMEOUT_4000_TO_1300MS 13
#define	PCFE_CZ_CMPL_TIMEOUT_1000_TO_3500MS 10
#define	PCFE_CZ_CMPL_TIMEOUT_260_TO_900MS 9
#define	PCFE_CZ_CMPL_TIMEOUT_65_TO_210MS 6
#define	PCFE_CZ_CMPL_TIMEOUT_16_TO_55MS 5
#define	PCFE_CZ_CMPL_TIMEOUT_1_TO_10MS 2
#define	PCFE_CZ_CMPL_TIMEOUT_50_TO_100US 1
#define	PCFE_CZ_CMPL_TIMEOUT_DEFAULT 0


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_CAP_CTL_REG(32bit):
 * AER capability and control register
 */
#define	PCR_AZ_AER_CAP_CTL_REG 0x00000118
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_ECRC_CHK_EN_LBN 8
#define	PCRF_AZ_ECRC_CHK_EN_WIDTH 1
#define	PCRF_AZ_ECRC_CHK_CAP_LBN 7
#define	PCRF_AZ_ECRC_CHK_CAP_WIDTH 1
#define	PCRF_AZ_ECRC_GEN_EN_LBN 6
#define	PCRF_AZ_ECRC_GEN_EN_WIDTH 1
#define	PCRF_AZ_ECRC_GEN_CAP_LBN 5
#define	PCRF_AZ_ECRC_GEN_CAP_WIDTH 1
#define	PCRF_AZ_1ST_ERR_PTR_LBN 0
#define	PCRF_AZ_1ST_ERR_PTR_WIDTH 5


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_BAR0_REG(32bit):
 * SRIOV VF Bar0
 */
#define	PCR_CZ_SRIOV_BAR0_REG 0x00000184
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_BAR_ADDRESS_LBN 0
#define	PCRF_CZ_VF_BAR_ADDRESS_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_BAR1_REG(32bit):
 * SRIOV Bar1
 */
#define	PCR_CZ_SRIOV_BAR1_REG 0x00000188
/* sienaa0=pci_f0_config */

/* defined as PCRF_CZ_VF_BAR_ADDRESS_LBN 0; access=rw reset=0x0 */
/* defined as PCRF_CZ_VF_BAR_ADDRESS_WIDTH 32 */


/*------------------------------------------------------------*/
/*
 * PCR_AZ_ACK_LAT_TMR_REG(32bit):
 * ACK latency timer & replay timer register
 */
#define	PCR_AZ_ACK_LAT_TMR_REG 0x00000700
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_RT_LBN 16
#define	PCRF_AZ_RT_WIDTH 16
#define	PCRF_AZ_ALT_LBN 0
#define	PCRF_AZ_ALT_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SYM_TMR_FLT_MSK_REG(16bit):
 * Symbol timer and Filter Mask Register
 */
#define	PCR_CZ_SYM_TMR_FLT_MSK_REG 0x0000071c
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_ET_LBN 11
#define	PCRF_CZ_ET_WIDTH 4
#define	PCRF_CZ_SI1_LBN 8
#define	PCRF_CZ_SI1_WIDTH 3
#define	PCRF_CZ_SI0_LBN 0
#define	PCRF_CZ_SI0_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_FLT_MSK_REG(32bit):
 * Filter Mask Register 2
 */
#define	PCR_CZ_FLT_MSK_REG 0x00000720
/* sienaa0=pci_f0_config */



/*------------------------------------------------------------*/
/*
 * PCR_AZ_XCFCC_STAT_REG(24bit):
 * documentation to be written for sum_PC_XCFCC_STAT_REG
 */
#define	PCR_AZ_XCFCC_STAT_REG 0x00000738
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_XCDC_LBN 12
#define	PCRF_AZ_XCDC_WIDTH 8
#define	PCRF_AZ_XCHC_LBN 0
#define	PCRF_AZ_XCHC_WIDTH 12


/*------------------------------------------------------------*/
/*
 * PCR_AZ_MSI_ADR_LO_REG(32bit):
 * MSI low 32 bits address register
 */
#define	PCR_AZ_MSI_ADR_LO_REG 0x00000054
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_MSI_ADR_LO_LBN 2
#define	PCRF_AZ_MSI_ADR_LO_WIDTH 30


/*------------------------------------------------------------*/
/*
 * PCR_AB_SLOT_CAP_REG(32bit):
 * PCIe slot capabilities register
 */
#define	PCR_AB_SLOT_CAP_REG 0x00000074
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_SLOT_NUM_LBN 19
#define	PCRF_AB_SLOT_NUM_WIDTH 13
#define	PCRF_AB_SLOT_PWR_LIM_SCL_LBN 15
#define	PCRF_AB_SLOT_PWR_LIM_SCL_WIDTH 2
#define	PCRF_AB_SLOT_PWR_LIM_VAL_LBN 7
#define	PCRF_AB_SLOT_PWR_LIM_VAL_WIDTH 8
#define	PCRF_AB_SLOT_HP_CAP_LBN 6
#define	PCRF_AB_SLOT_HP_CAP_WIDTH 1
#define	PCRF_AB_SLOT_HP_SURP_LBN 5
#define	PCRF_AB_SLOT_HP_SURP_WIDTH 1
#define	PCRF_AB_SLOT_PWR_IND_PRST_LBN 4
#define	PCRF_AB_SLOT_PWR_IND_PRST_WIDTH 1
#define	PCRF_AB_SLOT_ATTN_IND_PRST_LBN 3
#define	PCRF_AB_SLOT_ATTN_IND_PRST_WIDTH 1
#define	PCRF_AB_SLOT_MRL_SENS_PRST_LBN 2
#define	PCRF_AB_SLOT_MRL_SENS_PRST_WIDTH 1
#define	PCRF_AB_SLOT_PWR_CTL_PRST_LBN 1
#define	PCRF_AB_SLOT_PWR_CTL_PRST_WIDTH 1
#define	PCRF_AB_SLOT_ATTN_BUT_PRST_LBN 0
#define	PCRF_AB_SLOT_ATTN_BUT_PRST_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_BAR0_REG(32bit):
 * Primary function base address register 0
 */
#define	PCR_AZ_BAR0_REG 0x00000010
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_BAR0_LBN 4
#define	PCRF_AZ_BAR0_WIDTH 28
#define	PCRF_AZ_BAR0_PREF_LBN 3
#define	PCRF_AZ_BAR0_PREF_WIDTH 1
#define	PCRF_AZ_BAR0_TYPE_LBN 1
#define	PCRF_AZ_BAR0_TYPE_WIDTH 2
#define	PCRF_AZ_BAR0_IOM_LBN 0
#define	PCRF_AZ_BAR0_IOM_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_PCIE_CAP_REG(16bit):
 * PCIe capability register
 */
#define	PCR_CZ_PCIE_CAP_REG 0x00000072
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_PCIE_CAP_REG(16bit):
 * PCIe capability register
 */
#define	PCR_AB_PCIE_CAP_REG 0x00000062
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_PCIE_INT_MSG_NUM_LBN 9
#define	PCRF_AZ_PCIE_INT_MSG_NUM_WIDTH 5
#define	PCRF_AZ_PCIE_SLOT_IMP_LBN 8
#define	PCRF_AZ_PCIE_SLOT_IMP_WIDTH 1
#define	PCRF_AZ_PCIE_DEV_PORT_TYPE_LBN 4
#define	PCRF_AZ_PCIE_DEV_PORT_TYPE_WIDTH 4
#define	PCRF_AZ_PCIE_CAP_VER_LBN 0
#define	PCRF_AZ_PCIE_CAP_VER_WIDTH 4


/*------------------------------------------------------------*/
/*
 * PCR_CZ_LNK_CTL2_REG(16bit):
 * PCIe Link Control 2
 */
#define	PCR_CZ_LNK_CTL2_REG 0x000000a0
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_POLLING_DEEMPH_LVL_LBN 12
#define	PCRF_CZ_POLLING_DEEMPH_LVL_WIDTH 1
#define	PCRF_CZ_COMPLIANCE_SOS_CTL_LBN 11
#define	PCRF_CZ_COMPLIANCE_SOS_CTL_WIDTH 1
#define	PCRF_CZ_ENTER_MODIFIED_COMPLIANCE_CTL_LBN 10
#define	PCRF_CZ_ENTER_MODIFIED_COMPLIANCE_CTL_WIDTH 1
#define	PCRF_CZ_TRANSMIT_MARGIN_LBN 7
#define	PCRF_CZ_TRANSMIT_MARGIN_WIDTH 3
#define	PCRF_CZ_SELECT_DEEMPH_LBN 6
#define	PCRF_CZ_SELECT_DEEMPH_WIDTH 1
#define	PCRF_CZ_HW_AUTONOMOUS_SPEED_DIS_LBN 5
#define	PCRF_CZ_HW_AUTONOMOUS_SPEED_DIS_WIDTH 1
#define	PCRF_CZ_ENTER_COMPLIANCE_CTL_LBN 4
#define	PCRF_CZ_ENTER_COMPLIANCE_CTL_WIDTH 1
#define	PCRF_CZ_TGT_LNK_SPEED_CTL_LBN 0
#define	PCRF_CZ_TGT_LNK_SPEED_CTL_WIDTH 4


/*------------------------------------------------------------*/
/*
 * PCR_CZ_MSIX_PBA_BASE_REG(32bit):
 * MSIX Capability PBA Base
 */
#define	PCR_CZ_MSIX_PBA_BASE_REG 0x000000b8
/* sienaa0=pci_f0_config */
/*
 * PCR_BB_MSIX_PBA_BASE_REG(32bit):
 * MSIX Capability PBA Base
 */
#define	PCR_BB_MSIX_PBA_BASE_REG 0x00000098
/* falconb0=pci_f0_config */

#define	PCRF_BZ_MSIX_PBA_OFF_LBN 3
#define	PCRF_BZ_MSIX_PBA_OFF_WIDTH 29
#define	PCRF_BZ_MSIX_PBA_BIR_LBN 0
#define	PCRF_BZ_MSIX_PBA_BIR_WIDTH 3


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_TOTALVFS_REG(10bit):
 * SRIOV Total VFs
 */
#define	PCR_CZ_SRIOV_TOTALVFS_REG 0x0000016e
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_TOTALVFS_LBN 0
#define	PCRF_CZ_VF_TOTALVFS_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEVSN_DWORD0_REG(32bit):
 * Device serial number DWORD0
 */
#define	PCR_CZ_DEVSN_DWORD0_REG 0x00000144
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_DEVSN_DWORD0_LBN 0
#define	PCRF_CZ_DEVSN_DWORD0_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_CTL_REG(16bit):
 * SRIOV Control
 */
#define	PCR_CZ_SRIOV_CTL_REG 0x00000168
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_ARI_CAP_HRCHY_LBN 4
#define	PCRF_CZ_VF_ARI_CAP_HRCHY_WIDTH 1
#define	PCRF_CZ_VF_MSE_LBN 3
#define	PCRF_CZ_VF_MSE_WIDTH 1
#define	PCRF_CZ_VF_MIGR_INT_EN_LBN 2
#define	PCRF_CZ_VF_MIGR_INT_EN_WIDTH 1
#define	PCRF_CZ_VF_MIGR_EN_LBN 1
#define	PCRF_CZ_VF_MIGR_EN_WIDTH 1
#define	PCRF_CZ_VF_EN_LBN 0
#define	PCRF_CZ_VF_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_NUMVFS_REG(16bit):
 * SRIOV Number of VFs
 */
#define	PCR_CZ_SRIOV_NUMVFS_REG 0x00000170
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_NUMVFS_LBN 0
#define	PCRF_CZ_VF_NUMVFS_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_SUP_PAGESZ_REG(16bit):
 * SRIOV Supported Page Sizes
 */
#define	PCR_CZ_SRIOV_SUP_PAGESZ_REG 0x0000017c
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_SUP_PAGESZ_LBN 0
#define	PCRF_CZ_VF_SUP_PAGESZ_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_BAR3_REG(32bit):
 * SRIOV Bar3
 */
#define	PCR_CZ_SRIOV_BAR3_REG 0x00000190
/* sienaa0=pci_f0_config */

/* defined as PCRF_CZ_VF_BAR_ADDRESS_LBN 0; access=rw reset=0x0 */
/* defined as PCRF_CZ_VF_BAR_ADDRESS_WIDTH 32 */


/*------------------------------------------------------------*/
/*
 * PCR_CZ_VC0_P_RQ_CTL_REG(32bit):
 * VC0 Posted Receive Queue Control
 */
#define	PCR_CZ_VC0_P_RQ_CTL_REG 0x00000748
/* sienaa0=pci_f0_config */



/*------------------------------------------------------------*/
/*
 * PCR_AZ_PM_CAP_REG(16bit):
 * Power management capabilities register
 */
#define	PCR_AZ_PM_CAP_REG 0x00000042
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_PM_PME_SUPT_LBN 11
#define	PCRF_AZ_PM_PME_SUPT_WIDTH 5
#define	PCRF_AZ_PM_D2_SUPT_LBN 10
#define	PCRF_AZ_PM_D2_SUPT_WIDTH 1
#define	PCRF_AZ_PM_D1_SUPT_LBN 9
#define	PCRF_AZ_PM_D1_SUPT_WIDTH 1
#define	PCRF_AZ_PM_AUX_CURR_LBN 6
#define	PCRF_AZ_PM_AUX_CURR_WIDTH 3
#define	PCRF_AZ_PM_DSI_LBN 5
#define	PCRF_AZ_PM_DSI_WIDTH 1
#define	PCRF_AZ_PM_PME_CLK_LBN 3
#define	PCRF_AZ_PM_PME_CLK_WIDTH 1
#define	PCRF_AZ_PM_PME_VER_LBN 0
#define	PCRF_AZ_PM_PME_VER_WIDTH 3


/*------------------------------------------------------------*/
/*
 * PCR_AB_LNK_CTL_REG(16bit):
 * PCIe link control register
 */
#define	PCR_AB_LNK_CTL_REG 0x00000070
/* falcona0,falconb0=pci_f0_config */
/*
 * PCR_CZ_LNK_CTL_REG(16bit):
 * PCIe link control register
 */
#define	PCR_CZ_LNK_CTL_REG 0x00000080
/* sienaa0=pci_f0_config */

#define	PCRF_AZ_EXT_SYNC_LBN 7
#define	PCRF_AZ_EXT_SYNC_WIDTH 1
#define	PCRF_AZ_COMM_CLK_CFG_LBN 6
#define	PCRF_AZ_COMM_CLK_CFG_WIDTH 1
#define	PCRF_AB_LNK_CTL_REG_RSVD0_LBN 5
#define	PCRF_AB_LNK_CTL_REG_RSVD0_WIDTH 1
#define	PCRF_CZ_LNK_RETRAIN_LBN 5
#define	PCRF_CZ_LNK_RETRAIN_WIDTH 1
#define	PCRF_AZ_LNK_DIS_LBN 4
#define	PCRF_AZ_LNK_DIS_WIDTH 1
#define	PCRF_AZ_RD_COM_BDRY_LBN 3
#define	PCRF_AZ_RD_COM_BDRY_WIDTH 1
#define	PCRF_AZ_ACT_ST_LNK_PM_CTL_LBN 0
#define	PCRF_AZ_ACT_ST_LNK_PM_CTL_WIDTH 2


/*------------------------------------------------------------*/
/*
 * PCR_BB_MSIX_TBL_BASE_REG(32bit):
 * MSIX Capability Vector Table Base
 */
#define	PCR_BB_MSIX_TBL_BASE_REG 0x00000094
/* falconb0=pci_f0_config */
/*
 * PCR_CZ_MSIX_TBL_BASE_REG(32bit):
 * MSIX Capability Vector Table Base
 */
#define	PCR_CZ_MSIX_TBL_BASE_REG 0x000000b4
/* sienaa0=pci_f0_config */

#define	PCRF_BZ_MSIX_TBL_OFF_LBN 3
#define	PCRF_BZ_MSIX_TBL_OFF_WIDTH 29
#define	PCRF_BZ_MSIX_TBL_BIR_LBN 0
#define	PCRF_BZ_MSIX_TBL_BIR_WIDTH 3


/*------------------------------------------------------------*/
/*
 * PCR_AZ_XPFCC_STAT_REG(24bit):
 * documentation to be written for sum_PC_XPFCC_STAT_REG
 */
#define	PCR_AZ_XPFCC_STAT_REG 0x00000730
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_XPDC_LBN 12
#define	PCRF_AZ_XPDC_WIDTH 8
#define	PCRF_AZ_XPHC_LBN 0
#define	PCRF_AZ_XPHC_WIDTH 12


/*------------------------------------------------------------*/
/*
 * PCR_AZ_XNPFCC_STAT_REG(24bit):
 * documentation to be written for sum_PC_XNPFCC_STAT_REG
 */
#define	PCR_AZ_XNPFCC_STAT_REG 0x00000734
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_XNPDC_LBN 12
#define	PCRF_AZ_XNPDC_WIDTH 8
#define	PCRF_AZ_XNPHC_LBN 0
#define	PCRF_AZ_XNPHC_WIDTH 12


/*------------------------------------------------------------*/
/*
 * PCR_CZ_MSIX_CAP_ID_REG(8bit):
 * MSIX Capability ID
 */
#define	PCR_CZ_MSIX_CAP_ID_REG 0x000000b0
/* sienaa0=pci_f0_config */
/*
 * PCR_BB_MSIX_CAP_ID_REG(8bit):
 * MSIX Capability ID
 */
#define	PCR_BB_MSIX_CAP_ID_REG 0x00000090
/* falconb0=pci_f0_config */

#define	PCRF_BZ_MSIX_CAP_ID_LBN 0
#define	PCRF_BZ_MSIX_CAP_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_DEVSN_CAP_HDR_REG(32bit):
 * Device serial number capability header register
 */
#define	PCR_CZ_DEVSN_CAP_HDR_REG 0x00000140
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_DEVSNCAPHDR_NXT_PTR_LBN 20
#define	PCRF_CZ_DEVSNCAPHDR_NXT_PTR_WIDTH 12
#define	PCRF_CZ_DEVSNCAPHDR_VER_LBN 16
#define	PCRF_CZ_DEVSNCAPHDR_VER_WIDTH 4
#define	PCRF_CZ_DEVSNCAPHDR_ID_LBN 0
#define	PCRF_CZ_DEVSNCAPHDR_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_ARI_CAP_HDR_REG(32bit):
 * ARI capability header register
 */
#define	PCR_CZ_ARI_CAP_HDR_REG 0x00000150
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_ARICAPHDR_NXT_PTR_LBN 20
#define	PCRF_CZ_ARICAPHDR_NXT_PTR_WIDTH 12
#define	PCRF_CZ_ARICAPHDR_VER_LBN 16
#define	PCRF_CZ_ARICAPHDR_VER_WIDTH 4
#define	PCRF_CZ_ARICAPHDR_ID_LBN 0
#define	PCRF_CZ_ARICAPHDR_ID_WIDTH 16


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_BAR4_REG(32bit):
 * SRIOV Bar4
 */
#define	PCR_CZ_SRIOV_BAR4_REG 0x00000194
/* sienaa0=pci_f0_config */

/* defined as PCRF_CZ_VF_BAR_ADDRESS_LBN 0; access=rw reset=0x0 */
/* defined as PCRF_CZ_VF_BAR_ADDRESS_WIDTH 32 */


/*------------------------------------------------------------*/
/*
 * PCR_CZ_VC0_C_RQ_CTL_REG(32bit):
 * VC0 Completion Receive Queue Control
 */
#define	PCR_CZ_VC0_C_RQ_CTL_REG 0x00000750
/* sienaa0=pci_f0_config */



/*------------------------------------------------------------*/
/*
 * PCR_AZ_LN_SKEW_REG(32bit):
 * Lane skew register
 */
#define	PCR_AZ_LN_SKEW_REG 0x00000714
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_DIS_LBN 31
#define	PCRF_AZ_DIS_WIDTH 1
#define	PCRF_AB_RST_LBN 30
#define	PCRF_AB_RST_WIDTH 1
#define	PCRF_AZ_AD_LBN 25
#define	PCRF_AZ_AD_WIDTH 1
#define	PCRF_AZ_FCD_LBN 24
#define	PCRF_AZ_FCD_WIDTH 1
#define	PCRF_AZ_LS2_LBN 16
#define	PCRF_AZ_LS2_WIDTH 8
#define	PCRF_AZ_LS1_LBN 8
#define	PCRF_AZ_LS1_WIDTH 8
#define	PCRF_AZ_LS0_LBN 0
#define	PCRF_AZ_LS0_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_CAP_REG(32bit):
 * SRIOV Capabilities
 */
#define	PCR_CZ_SRIOV_CAP_REG 0x00000164
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_MIGR_INT_MSG_NUM_LBN 21
#define	PCRF_CZ_VF_MIGR_INT_MSG_NUM_WIDTH 11
#define	PCRF_CZ_VF_MIGR_CAP_LBN 0
#define	PCRF_CZ_VF_MIGR_CAP_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_BAR5_REG(32bit):
 * SRIOV Bar5
 */
#define	PCR_CZ_SRIOV_BAR5_REG 0x00000198
/* sienaa0=pci_f0_config */

/* defined as PCRF_CZ_VF_BAR_ADDRESS_LBN 0; access=rw reset=0x0 */
/* defined as PCRF_CZ_VF_BAR_ADDRESS_WIDTH 32 */


/*------------------------------------------------------------*/
/*
 * PCR_AZ_DEBUG1_REG(32bit):
 * Debug register 1
 */
#define	PCR_AZ_DEBUG1_REG 0x0000072c
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_CDI13_LBN 24
#define	PCRF_AZ_CDI13_WIDTH 8
#define	PCRF_AZ_CDI1_LBN 0
#define	PCRF_AZ_CDI1_WIDTH 32
#define	PCRF_AZ_CDI12_LBN 16
#define	PCRF_AZ_CDI12_WIDTH 8
#define	PCRF_AZ_CDI11_LBN 8
#define	PCRF_AZ_CDI11_WIDTH 8
#define	PCRF_AZ_CDI10_LBN 0
#define	PCRF_AZ_CDI10_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_CZ_PHY_STAT_REG(32bit):
 * PHY status register
 */
#define	PCR_CZ_PHY_STAT_REG 0x00000810
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_PHY_STAT_REG(8bit):
 * PHY status register
 */
#define	PCR_AB_PHY_STAT_REG 0x00000720
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_SSL_LBN 3
#define	PCRF_AZ_SSL_WIDTH 1
#define	PCRF_AZ_SSR_LBN 2
#define	PCRF_AZ_SSR_WIDTH 1
#define	PCRF_AZ_SSCL_LBN 1
#define	PCRF_AZ_SSCL_WIDTH 1
#define	PCRF_AZ_SSCD_LBN 0
#define	PCRF_AZ_SSCD_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_GEN2_REG(32bit):
 * Gen2 Register
 */
#define	PCR_CZ_GEN2_REG 0x0000080c
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_SET_DE_EMPHASIS_LBN 20
#define	PCRF_CZ_SET_DE_EMPHASIS_WIDTH 1
#define	PCRF_CZ_CFG_TX_COMPLIANCE_LBN 19
#define	PCRF_CZ_CFG_TX_COMPLIANCE_WIDTH 1
#define	PCRF_CZ_CFG_TX_SWING_LBN 18
#define	PCRF_CZ_CFG_TX_SWING_WIDTH 1
#define	PCRF_CZ_DIR_SPEED_CHANGE_LBN 17
#define	PCRF_CZ_DIR_SPEED_CHANGE_WIDTH 1
#define	PCRF_CZ_LANE_ENABLE_LBN 8
#define	PCRF_CZ_LANE_ENABLE_WIDTH 9
#define	PCRF_CZ_NUM_FTS_LBN 0
#define	PCRF_CZ_NUM_FTS_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_BAR2_LO_REG(32bit):
 * Primary function base address register 2 low bits
 */
#define	PCR_AZ_BAR2_LO_REG 0x00000018
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_BAR2_LO_LBN 4
#define	PCRF_AZ_BAR2_LO_WIDTH 28
#define	PCRF_AZ_BAR2_PREF_LBN 3
#define	PCRF_AZ_BAR2_PREF_WIDTH 1
#define	PCRF_AZ_BAR2_TYPE_LBN 1
#define	PCRF_AZ_BAR2_TYPE_WIDTH 2
#define	PCRF_AZ_BAR2_IOM_LBN 0
#define	PCRF_AZ_BAR2_IOM_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_PM_NXT_PTR_REG(8bit):
 * Power management next item pointer
 */
#define	PCR_AZ_PM_NXT_PTR_REG 0x00000041
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_PM_NXT_PTR_LBN 0
#define	PCRF_AZ_PM_NXT_PTR_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AB_SLOT_CTL_REG(16bit):
 * PCIe slot control register
 */
#define	PCR_AB_SLOT_CTL_REG 0x00000078
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_SLOT_PWR_CTLR_CTL_LBN 10
#define	PCRF_AB_SLOT_PWR_CTLR_CTL_WIDTH 1
#define	PCRF_AB_SLOT_PWR_IND_CTL_LBN 8
#define	PCRF_AB_SLOT_PWR_IND_CTL_WIDTH 2
#define	PCRF_AB_SLOT_ATT_IND_CTL_LBN 6
#define	PCRF_AB_SLOT_ATT_IND_CTL_WIDTH 2
#define	PCRF_AB_SLOT_HP_INT_EN_LBN 5
#define	PCRF_AB_SLOT_HP_INT_EN_WIDTH 1
#define	PCRF_AB_SLOT_CMD_COMP_INT_EN_LBN 4
#define	PCRF_AB_SLOT_CMD_COMP_INT_EN_WIDTH 1
#define	PCRF_AB_SLOT_PRES_DET_CHG_EN_LBN 3
#define	PCRF_AB_SLOT_PRES_DET_CHG_EN_WIDTH 1
#define	PCRF_AB_SLOT_MRL_SENS_CHG_EN_LBN 2
#define	PCRF_AB_SLOT_MRL_SENS_CHG_EN_WIDTH 1
#define	PCRF_AB_SLOT_PWR_FLTDET_EN_LBN 1
#define	PCRF_AB_SLOT_PWR_FLTDET_EN_WIDTH 1
#define	PCRF_AB_SLOT_ATTN_BUT_EN_LBN 0
#define	PCRF_AB_SLOT_ATTN_BUT_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AB_VPD_CAP_ID_REG(8bit):
 * VPD data register
 */
#define	PCR_AB_VPD_CAP_ID_REG 0x000000b0
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_VPD_CAP_ID_LBN 0
#define	PCRF_AB_VPD_CAP_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AB_VPD_NXT_PTR_REG(8bit):
 * VPD next item pointer
 */
#define	PCR_AB_VPD_NXT_PTR_REG 0x000000b1
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_VPD_NXT_PTR_LBN 0
#define	PCRF_AB_VPD_NXT_PTR_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_UNCORR_ERR_STAT_REG(32bit):
 * AER Uncorrectable error status register
 */
#define	PCR_AZ_AER_UNCORR_ERR_STAT_REG 0x00000104
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_UNSUPT_REQ_ERR_STAT_LBN 20
#define	PCRF_AZ_UNSUPT_REQ_ERR_STAT_WIDTH 1
#define	PCRF_AZ_ECRC_ERR_STAT_LBN 19
#define	PCRF_AZ_ECRC_ERR_STAT_WIDTH 1
#define	PCRF_AZ_MALF_TLP_STAT_LBN 18
#define	PCRF_AZ_MALF_TLP_STAT_WIDTH 1
#define	PCRF_AZ_RX_OVF_STAT_LBN 17
#define	PCRF_AZ_RX_OVF_STAT_WIDTH 1
#define	PCRF_AZ_UNEXP_COMP_STAT_LBN 16
#define	PCRF_AZ_UNEXP_COMP_STAT_WIDTH 1
#define	PCRF_AZ_COMP_ABRT_STAT_LBN 15
#define	PCRF_AZ_COMP_ABRT_STAT_WIDTH 1
#define	PCRF_AZ_COMP_TIMEOUT_STAT_LBN 14
#define	PCRF_AZ_COMP_TIMEOUT_STAT_WIDTH 1
#define	PCRF_AZ_FC_PROTO_ERR_STAT_LBN 13
#define	PCRF_AZ_FC_PROTO_ERR_STAT_WIDTH 1
#define	PCRF_AZ_PSON_TLP_STAT_LBN 12
#define	PCRF_AZ_PSON_TLP_STAT_WIDTH 1
#define	PCRF_AZ_DL_PROTO_ERR_STAT_LBN 4
#define	PCRF_AZ_DL_PROTO_ERR_STAT_WIDTH 1
#define	PCRF_AB_TRAIN_ERR_STAT_LBN 0
#define	PCRF_AB_TRAIN_ERR_STAT_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_STAT_REG(16bit):
 * Status register
 */
#define	PCR_AZ_STAT_REG 0x00000006
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_DET_PERR_LBN 15
#define	PCRF_AZ_DET_PERR_WIDTH 1
#define	PCRF_AZ_SIG_SERR_LBN 14
#define	PCRF_AZ_SIG_SERR_WIDTH 1
#define	PCRF_AZ_GOT_MABRT_LBN 13
#define	PCRF_AZ_GOT_MABRT_WIDTH 1
#define	PCRF_AZ_GOT_TABRT_LBN 12
#define	PCRF_AZ_GOT_TABRT_WIDTH 1
#define	PCRF_AZ_SIG_TABRT_LBN 11
#define	PCRF_AZ_SIG_TABRT_WIDTH 1
#define	PCRF_AZ_DEVSEL_TIM_LBN 9
#define	PCRF_AZ_DEVSEL_TIM_WIDTH 2
#define	PCRF_AZ_MDAT_PERR_LBN 8
#define	PCRF_AZ_MDAT_PERR_WIDTH 1
#define	PCRF_AZ_FB2B_CAP_LBN 7
#define	PCRF_AZ_FB2B_CAP_WIDTH 1
#define	PCRF_AZ_66MHZ_CAP_LBN 5
#define	PCRF_AZ_66MHZ_CAP_WIDTH 1
#define	PCRF_AZ_CAP_LIST_LBN 4
#define	PCRF_AZ_CAP_LIST_WIDTH 1
#define	PCRF_AZ_INTX_STAT_LBN 3
#define	PCRF_AZ_INTX_STAT_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_BAR4_HI_REG(32bit):
 * Primary function base address register 2 high bits
 */
#define	PCR_CZ_BAR4_HI_REG 0x00000024
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_BAR4_HI_LBN 0
#define	PCRF_CZ_BAR4_HI_WIDTH 32


/*------------------------------------------------------------*/
/*
 * PCR_CZ_LNK_STAT_REG(16bit):
 * PCIe link status register
 */
#define	PCR_CZ_LNK_STAT_REG 0x00000082
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_LNK_STAT_REG(16bit):
 * PCIe link status register
 */
#define	PCR_AB_LNK_STAT_REG 0x00000072
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_SLOT_CLK_CFG_LBN 12
#define	PCRF_AZ_SLOT_CLK_CFG_WIDTH 1
#define	PCRF_AZ_LNK_TRAIN_LBN 11
#define	PCRF_AZ_LNK_TRAIN_WIDTH 1
#define	PCRF_AB_TRAIN_ERR_LBN 10
#define	PCRF_AB_TRAIN_ERR_WIDTH 1
#define	PCRF_AZ_LNK_WIDTH_LBN 4
#define	PCRF_AZ_LNK_WIDTH_WIDTH 6
#define	PCRF_AZ_LNK_SP_LBN 0
#define	PCRF_AZ_LNK_SP_WIDTH 4


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_CORR_ERR_MASK_REG(32bit):
 * AER Correctable error status register
 */
#define	PCR_AZ_AER_CORR_ERR_MASK_REG 0x00000114
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_CZ_ADVSY_NON_FATAL_MASK_LBN 13
#define	PCRF_CZ_ADVSY_NON_FATAL_MASK_WIDTH 1
#define	PCRF_AZ_RPLY_TMR_TOUT_MASK_LBN 12
#define	PCRF_AZ_RPLY_TMR_TOUT_MASK_WIDTH 1
#define	PCRF_AZ_RPLAY_NUM_RO_MASK_LBN 8
#define	PCRF_AZ_RPLAY_NUM_RO_MASK_WIDTH 1
#define	PCRF_AZ_BAD_DLLP_MASK_LBN 7
#define	PCRF_AZ_BAD_DLLP_MASK_WIDTH 1
#define	PCRF_AZ_BAD_TLP_MASK_LBN 6
#define	PCRF_AZ_BAD_TLP_MASK_WIDTH 1
#define	PCRF_AZ_RX_ERR_MASK_LBN 0
#define	PCRF_AZ_RX_ERR_MASK_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_SYM_NUM_REG(16bit):
 * Symbol number register
 */
#define	PCR_AZ_SYM_NUM_REG 0x00000718
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_CZ_MAX_FUNCTIONS_LBN 29
#define	PCRF_CZ_MAX_FUNCTIONS_WIDTH 3
#define	PCRF_CZ_FC_WATCHDOG_TMR_LBN 24
#define	PCRF_CZ_FC_WATCHDOG_TMR_WIDTH 5
#define	PCRF_CZ_ACK_NAK_TMR_MOD_LBN 19
#define	PCRF_CZ_ACK_NAK_TMR_MOD_WIDTH 5
#define	PCRF_CZ_REPLAY_TMR_MOD_LBN 14
#define	PCRF_CZ_REPLAY_TMR_MOD_WIDTH 5
#define	PCRF_AB_ES_LBN 12
#define	PCRF_AB_ES_WIDTH 3
#define	PCRF_AB_SYM_NUM_REG_RSVD0_LBN 11
#define	PCRF_AB_SYM_NUM_REG_RSVD0_WIDTH 1
#define	PCRF_CZ_NUM_SKP_SYMS_LBN 8
#define	PCRF_CZ_NUM_SKP_SYMS_WIDTH 3
#define	PCRF_AB_TS2_LBN 4
#define	PCRF_AB_TS2_WIDTH 4
#define	PCRF_AZ_TS1_LBN 0
#define	PCRF_AZ_TS1_WIDTH 4


/*------------------------------------------------------------*/
/*
 * PCR_AZ_Q_STAT_REG(8bit):
 * documentation to be written for sum_PC_Q_STAT_REG
 */
#define	PCR_AZ_Q_STAT_REG 0x0000073c
/* falcona0,falconb0=pci_f0_config,sienaa0=pci_f0_config */

#define	PCRF_AZ_RQNE_LBN 2
#define	PCRF_AZ_RQNE_WIDTH 1
#define	PCRF_AZ_XRNE_LBN 1
#define	PCRF_AZ_XRNE_WIDTH 1
#define	PCRF_AZ_RCNR_LBN 0
#define	PCRF_AZ_RCNR_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_VPD_CAP_CTL_REG(8bit):
 * VPD control and capabilities register
 */
#define	PCR_CZ_VPD_CAP_CTL_REG 0x000000d0
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VPD_FLAG_LBN 31
#define	PCRF_CZ_VPD_FLAG_WIDTH 1
#define	PCRF_CZ_VPD_ADDR_LBN 16
#define	PCRF_CZ_VPD_ADDR_WIDTH 15
#define	PCRF_CZ_VPD_NXT_PTR_LBN 8
#define	PCRF_CZ_VPD_NXT_PTR_WIDTH 8
#define	PCRF_CZ_VPD_CAP_ID_LBN 0
#define	PCRF_CZ_VPD_CAP_ID_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AZ_AER_UNCORR_ERR_MASK_REG(32bit):
 * AER Uncorrectable error mask register
 */
#define	PCR_AZ_AER_UNCORR_ERR_MASK_REG 0x00000108
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_UNSUPT_REQ_ERR_MASK_LBN 20
#define	PCRF_AZ_UNSUPT_REQ_ERR_MASK_WIDTH 1
#define	PCRF_AZ_ECRC_ERR_MASK_LBN 19
#define	PCRF_AZ_ECRC_ERR_MASK_WIDTH 1
#define	PCRF_AZ_MALF_TLP_MASK_LBN 18
#define	PCRF_AZ_MALF_TLP_MASK_WIDTH 1
#define	PCRF_AZ_RX_OVF_MASK_LBN 17
#define	PCRF_AZ_RX_OVF_MASK_WIDTH 1
#define	PCRF_AZ_UNEXP_COMP_MASK_LBN 16
#define	PCRF_AZ_UNEXP_COMP_MASK_WIDTH 1
#define	PCRF_AZ_COMP_ABRT_MASK_LBN 15
#define	PCRF_AZ_COMP_ABRT_MASK_WIDTH 1
#define	PCRF_AZ_COMP_TIMEOUT_MASK_LBN 14
#define	PCRF_AZ_COMP_TIMEOUT_MASK_WIDTH 1
#define	PCRF_AZ_FC_PROTO_ERR_MASK_LBN 13
#define	PCRF_AZ_FC_PROTO_ERR_MASK_WIDTH 1
#define	PCRF_AZ_PSON_TLP_MASK_LBN 12
#define	PCRF_AZ_PSON_TLP_MASK_WIDTH 1
#define	PCRF_AZ_DL_PROTO_ERR_MASK_LBN 4
#define	PCRF_AZ_DL_PROTO_ERR_MASK_WIDTH 1
#define	PCRF_AB_TRAIN_ERR_MASK_LBN 0
#define	PCRF_AB_TRAIN_ERR_MASK_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_ARI_CAP_REG(16bit):
 * ARI Capabilities
 */
#define	PCR_CZ_ARI_CAP_REG 0x00000154
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_ARI_NXT_FN_NUM_LBN 8
#define	PCRF_CZ_ARI_NXT_FN_NUM_WIDTH 8
#define	PCRF_CZ_ARI_ACS_FNGRP_CAP_LBN 1
#define	PCRF_CZ_ARI_ACS_FNGRP_CAP_WIDTH 1
#define	PCRF_CZ_ARI_MFVC_FNGRP_CAP_LBN 0
#define	PCRF_CZ_ARI_MFVC_FNGRP_CAP_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_STAT_REG(16bit):
 * SRIOV Status
 */
#define	PCR_CZ_SRIOV_STAT_REG 0x0000016a
/* sienaa0=pci_f0_config */

#define	PCRF_CZ_VF_MIGR_STAT_LBN 0
#define	PCRF_CZ_VF_MIGR_STAT_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AZ_OTHER_MSG_REG(32bit):
 * Other message register
 */
#define	PCR_AZ_OTHER_MSG_REG 0x00000704
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_OM_CRPT3_LBN 24
#define	PCRF_AZ_OM_CRPT3_WIDTH 8
#define	PCRF_AZ_OM_CRPT2_LBN 16
#define	PCRF_AZ_OM_CRPT2_WIDTH 8
#define	PCRF_AZ_OM_CRPT1_LBN 8
#define	PCRF_AZ_OM_CRPT1_WIDTH 8
#define	PCRF_AZ_OM_CRPT0_LBN 0
#define	PCRF_AZ_OM_CRPT0_WIDTH 8


/*------------------------------------------------------------*/
/*
 * PCR_AB_SLOT_STAT_REG(16bit):
 * PCIe slot status register
 */
#define	PCR_AB_SLOT_STAT_REG 0x0000007a
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_PRES_DET_ST_LBN 6
#define	PCRF_AB_PRES_DET_ST_WIDTH 1
#define	PCRF_AB_MRL_SENS_ST_LBN 5
#define	PCRF_AB_MRL_SENS_ST_WIDTH 1
#define	PCRF_AB_SLOT_PWR_IND_LBN 4
#define	PCRF_AB_SLOT_PWR_IND_WIDTH 1
#define	PCRF_AB_SLOT_ATTN_IND_LBN 3
#define	PCRF_AB_SLOT_ATTN_IND_WIDTH 1
#define	PCRF_AB_SLOT_MRL_SENS_LBN 2
#define	PCRF_AB_SLOT_MRL_SENS_WIDTH 1
#define	PCRF_AB_PWR_FLTDET_LBN 1
#define	PCRF_AB_PWR_FLTDET_WIDTH 1
#define	PCRF_AB_ATTN_BUTDET_LBN 0
#define	PCRF_AB_ATTN_BUTDET_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_SRIOV_BAR2_REG(32bit):
 * SRIOV Bar2
 */
#define	PCR_CZ_SRIOV_BAR2_REG 0x0000018c
/* sienaa0=pci_f0_config */

/* defined as PCRF_CZ_VF_BAR_ADDRESS_LBN 0; access=rw reset=0x0 */
/* defined as PCRF_CZ_VF_BAR_ADDRESS_WIDTH 32 */


/*------------------------------------------------------------*/
/*
 * PCR_AZ_PORT_LNK_CTL_REG(32bit):
 * Port link control register
 */
#define	PCR_AZ_PORT_LNK_CTL_REG 0x00000710
/* sienaa0=pci_f0_config,falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_LRE_LBN 27
#define	PCRF_AZ_LRE_WIDTH 1
#define	PCRF_AZ_ESYNC_LBN 26
#define	PCRF_AZ_ESYNC_WIDTH 1
#define	PCRF_AZ_CRPT_LBN 25
#define	PCRF_AZ_CRPT_WIDTH 1
#define	PCRF_AZ_XB_LBN 24
#define	PCRF_AZ_XB_WIDTH 1
#define	PCRF_AZ_LC_LBN 16
#define	PCRF_AZ_LC_WIDTH 6
#define	PCRF_AZ_LDR_LBN 8
#define	PCRF_AZ_LDR_WIDTH 4
#define	PCRF_AZ_FLM_LBN 7
#define	PCRF_AZ_FLM_WIDTH 1
#define	PCRF_AZ_LKD_LBN 6
#define	PCRF_AZ_LKD_WIDTH 1
#define	PCRF_AZ_DLE_LBN 5
#define	PCRF_AZ_DLE_WIDTH 1
#define	PCRF_AZ_PORT_LNK_CTL_REG_RSVD0_LBN 4
#define	PCRF_AZ_PORT_LNK_CTL_REG_RSVD0_WIDTH 1
#define	PCRF_AZ_RA_LBN 3
#define	PCRF_AZ_RA_WIDTH 1
#define	PCRF_AZ_LE_LBN 2
#define	PCRF_AZ_LE_WIDTH 1
#define	PCRF_AZ_SD_LBN 1
#define	PCRF_AZ_SD_WIDTH 1
#define	PCRF_AZ_OMR_LBN 0
#define	PCRF_AZ_OMR_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_CZ_VC_XMIT_ARB1_REG(32bit):
 * VC Transmit Arbitration Register 1
 */
#define	PCR_CZ_VC_XMIT_ARB1_REG 0x00000740
/* sienaa0=pci_f0_config */



/*------------------------------------------------------------*/
/*
 * PCR_CZ_VC0_NP_RQ_CTL_REG(32bit):
 * VC0 Non-Posted Receive Queue Control
 */
#define	PCR_CZ_VC0_NP_RQ_CTL_REG 0x0000074c
/* sienaa0=pci_f0_config */



/*------------------------------------------------------------*/
/*
 * PCR_CZ_PHY_CTL_REG(32bit):
 * PHY control register
 */
#define	PCR_CZ_PHY_CTL_REG 0x00000814
/* sienaa0=pci_f0_config */
/*
 * PCR_AB_PHY_CTL_REG(32bit):
 * PHY control register
 */
#define	PCR_AB_PHY_CTL_REG 0x00000724
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AZ_BD_LBN 31
#define	PCRF_AZ_BD_WIDTH 1
#define	PCRF_AZ_CDS_LBN 30
#define	PCRF_AZ_CDS_WIDTH 1
#define	PCRF_AZ_DWRAP_LB_LBN 29
#define	PCRF_AZ_DWRAP_LB_WIDTH 1
#define	PCRF_AZ_EBD_LBN 28
#define	PCRF_AZ_EBD_WIDTH 1
#define	PCRF_AZ_SNR_LBN 27
#define	PCRF_AZ_SNR_WIDTH 1
#define	PCRF_AZ_RX_NOT_DET_LBN 2
#define	PCRF_AZ_RX_NOT_DET_WIDTH 1
#define	PCRF_AZ_FORCE_LOS_VAL_LBN 1
#define	PCRF_AZ_FORCE_LOS_VAL_WIDTH 1
#define	PCRF_AZ_FORCE_LOS_EN_LBN 0
#define	PCRF_AZ_FORCE_LOS_EN_WIDTH 1


/*------------------------------------------------------------*/
/*
 * PCR_AB_VPD_ADDR_REG(16bit):
 * VPD address register
 */
#define	PCR_AB_VPD_ADDR_REG 0x000000b2
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_VPD_FLAG_LBN 15
#define	PCRF_AB_VPD_FLAG_WIDTH 1
#define	PCRF_AB_VPD_ADDR_LBN 0
#define	PCRF_AB_VPD_ADDR_WIDTH 15


/*------------------------------------------------------------*/
/*
 * PCR_AB_SYM_TMR_REG(16bit):
 * Symbol timer register
 */
#define	PCR_AB_SYM_TMR_REG 0x0000071c
/* falcona0,falconb0=pci_f0_config */

#define	PCRF_AB_ET_LBN 11
#define	PCRF_AB_ET_WIDTH 4
#define	PCRF_AB_SI1_LBN 8
#define	PCRF_AB_SI1_WIDTH 3
#define	PCRF_AB_SI0_LBN 0
#define	PCRF_AB_SI0_WIDTH 8


#endif /* PCI_PROGMODEL_DEFS_H */
