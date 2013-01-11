/****************************************************************************
 * Driver for Solarflare network controllers -
 *          resource management for Xen backend, OpenOnload, etc
 *           (including support for SFE4001 10GBT NIC)
 *
 * This file provides struct efhw_nic and some related types.
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

#ifndef __CI_EFHW_EFAB_TYPES_H__
#define __CI_EFHW_EFAB_TYPES_H__

#include <ci/efhw/efhw_config.h>
#include <ci/efhw/hardware_sysdep.h>
#include <ci/efhw/iopage_types.h>
#include <ci/efhw/sysdep.h>

/*--------------------------------------------------------------------
 *
 * forward type declarations
 *
 *--------------------------------------------------------------------*/

struct efhw_nic;

/*--------------------------------------------------------------------
 *
 * Managed interface
 *
 *--------------------------------------------------------------------*/

struct efhw_buffer_table_allocation{
	unsigned base;
	unsigned order;
};

struct eventq_resource_hardware {
	/*!iobuffer allocated for eventq - can be larger than eventq */
	struct efhw_iopages iobuff;
	struct efhw_buffer_table_allocation buf_tbl_alloc;
	int capacity;		/*!< capacity of event queue */
};

/*--------------------------------------------------------------------
 *
 * event queues and event driven callbacks
 *
 *--------------------------------------------------------------------*/

struct efhw_keventq {
	int lock;
	caddr_t evq_base;
	int32_t evq_ptr;
	uint32_t evq_mask;
	unsigned instance;
	struct eventq_resource_hardware hw;
	struct efhw_ev_handler *ev_handlers;
};

/*--------------------------------------------------------------------
 *
 * filters
 *
 *--------------------------------------------------------------------*/

enum efhw_filter_type {
	EFHW_FILTER_TYPE_IP = 0,	/* always supported */
	EFHW_FILTER_TYPE_MAC,		/* supported by Siena only */
	EFHW_FILTER_TYPE_TX_IP,		/* supported by Siena only */
	EFHW_FILTER_TYPE_TX_MAC,	/* supported by Siena only */
	EFHW_FILTER_TYPES_NUM
};

struct efhw_filter_spec {
	enum efhw_filter_type type;
	uint dmaq_id;
	union {
		struct {
			uint32_t saddr_le32;
			uint32_t daddr_le32;
			uint16_t sport_le16;
			uint16_t dport_le16;
			unsigned tcp     : 1;
			unsigned full    : 1;
			unsigned rss     : 1;  /* not supported on A1 */
			unsigned scatter : 1;  /* not supported on A1 */
		} ip;
		struct {
			uint32_t saddr_le32;
			uint32_t daddr_le32;
			uint16_t sport_le16;
			uint16_t dport_le16;
			unsigned tcp  : 1;
			unsigned full : 1;
		} tx_ip;
		struct {
			uint8_t  mac[6];
			uint16_t vlan_tag;
			unsigned full        : 1;
			unsigned ip_override : 1;
			unsigned rss         : 1;
			unsigned scatter     : 1;
		} mac;
		struct {
			uint8_t  mac[6];
			uint16_t vlan_tag;
			unsigned full : 1;
		} tx_mac;
	} u;
};

struct efhw_filter_depth {
	unsigned needed;
	unsigned max;
};

struct efhw_filter_search_limits {
	unsigned tcp_full;
	unsigned tcp_wild;
	unsigned udp_full;
	unsigned udp_wild;
	unsigned mac_full;
	unsigned mac_wild;
};


/**********************************************************************
 * Portable HW interface. ***************************************
 **********************************************************************/

/*--------------------------------------------------------------------
 *
 * EtherFabric Functional units - configuration and control
 *
 *--------------------------------------------------------------------*/

struct efhw_func_ops {

  /*-------------- Initialisation ------------ */

	/*! close down all hardware functional units - leaves NIC in a safe
	   state for driver unload */
	void (*close_hardware) (struct efhw_nic *nic);

	/*! initialise all hardware functional units */
	int (*init_hardware) (struct efhw_nic *nic,
			      struct efhw_ev_handler *,
			      const uint8_t *mac_addr, int non_irq_evq);

  /*-------------- Interrupt support  ------------ */

	/*! Main interrupt routine
	 **        This function returns,
	 **  - zero,       if the IRQ was not generated by EF1
	 **  - non-zero,   if EF1 was the source of the IRQ
	 **
	 **
	 ** opaque is an OS provided pointer for use by the OS callbacks
	 ** e.g in Windows used to indicate DPC scheduled
	 */
	int (*interrupt) (struct efhw_nic *nic);

	/*! Enable the interrupt */
	void (*interrupt_enable) (struct efhw_nic *nic);

	/*! Disable the interrupt */
	void (*interrupt_disable) (struct efhw_nic *nic);

	/*! Set interrupt moderation strategy for the given IRQ unit
	 ** val is in usec
	 */
	void (*set_interrupt_moderation)(struct efhw_nic *nic, int evq,
					 uint val);

  /*-------------- Event support  ------------ */

	/*! Enable the given event queue
	   depending on the underlying implementation (EF1 or Falcon) then
	   either a q_base_addr in host memory, or a buffer base id should
	   be proivded
	 */
	void (*event_queue_enable) (struct efhw_nic *nic,
				    uint evq,	/* evnt queue index */
				    uint evq_size,	/* units of #entries */
				    uint buf_base_id,
				    int interrupting, 
				    int enable_dos_p);

	/*! Disable the given event queue (and any associated timer) */
	void (*event_queue_disable) (struct efhw_nic *nic, uint evq,
				     int timer_only);

	/*! request wakeup from the NIC on a given event Q */
	void (*wakeup_request) (struct efhw_nic *nic, int rd_ptr, int evq);

	/*! Push a SW event on a given eventQ */
	void (*sw_event) (struct efhw_nic *nic, int data, int evq);

  /*-------------- IP Filter API  ------------ */

	/*! Setup a given filter - The software can request a filter_i,
	 * but some EtherFabric implementations will override with
	 * a more suitable index
	 */
	int (*ipfilter_set) (struct efhw_nic *nic, int type,
			     int *filter_i, int dmaq,
			     unsigned saddr_be32, unsigned sport_be16,
			     unsigned daddr_be32, unsigned dport_be16);

	/*! Clear down a given filter */
	void (*ipfilter_clear) (struct efhw_nic *nic, int filter_idx);

	/*! Redirect given filter to a different RX DMAQ */
	void (*ipfilter_redirect) (struct efhw_nic *nic, int filter_i,
				   int rxq_i);

  /*-------------- DMA support  ------------ */

	/*! Initialise NIC state for a given TX DMAQ */
	void (*dmaq_tx_q_init) (struct efhw_nic *nic,
				uint dmaq, uint evq, uint owner, uint tag,
				uint dmaq_size, uint buf_idx, uint flags);

	/*! Initialise NIC state for a given RX DMAQ */
	void (*dmaq_rx_q_init) (struct efhw_nic *nic,
				uint dmaq, uint evq, uint owner, uint tag,
				uint dmaq_size, uint buf_idx, uint flags);

	/*! Disable a given TX DMAQ */
	void (*dmaq_tx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Disable a given RX DMAQ */
	void (*dmaq_rx_q_disable) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given TX DMA channel */
	int (*flush_tx_dma_channel) (struct efhw_nic *nic, uint dmaq);

	/*! Flush a given RX DMA channel */
	int (*flush_rx_dma_channel) (struct efhw_nic *nic, uint dmaq);

  /*-------------- Buffer table Support ------------ */

	/*! Initialise a buffer table page */
	void (*buffer_table_set) (struct efhw_nic *nic,
				  dma_addr_t dma_addr,
				  uint bufsz, uint region,
				  int own_id, int buffer_id);

	/*! Initialise a block of buffer table pages */
	void (*buffer_table_set_n) (struct efhw_nic *nic, int buffer_id,
				    dma_addr_t dma_addr,
				    uint bufsz, uint region,
				    int n_pages, int own_id);

	/*! Clear a block of buffer table pages */
	void (*buffer_table_clear) (struct efhw_nic *nic, int buffer_id,
				    int num);

	/*! Commit a buffer table update  */
	void (*buffer_table_commit) (struct efhw_nic *nic);

  /*-------------- New filter API ------------ */

	/*! Set a given filter */
	int (*filter_set) (struct efhw_nic *nic, struct efhw_filter_spec *spec,
			   int *filter_idx_out);

	/*! Clear a given filter */
	void (*filter_clear) (struct efhw_nic *nic, enum efhw_filter_type type,
			      int filter_idx);
};


/*----------------------------------------------------------------------------
 *
 * NIC type
 *
 *---------------------------------------------------------------------------*/

struct efhw_device_type {
	int  arch;            /* enum efhw_arch */
	char variant;         /* 'A', 'B', ... */
	int  revision;        /* 0, 1, ... */
	int  in_fpga:1;
	int  in_cosim:1;
};


/*----------------------------------------------------------------------------
 *
 * EtherFabric NIC instance - nic.c for HW independent functions
 *
 *---------------------------------------------------------------------------*/

/*! */
struct efhw_nic {
	/*! zero base index in efrm_nic_tablep->nic array */
	int index;
	int ifindex;		/*!< OS level nic index */
#ifdef HAS_NET_NAMESPACE
	struct net *nd_net;
#endif

	struct efhw_device_type devtype;

	/*! Options that can be set by user. */
	unsigned options;
# define NIC_OPT_EFTEST             0x1	/* owner is an eftest app */

# define NIC_OPT_DEFAULT            0

	/*! Internal flags that indicate hardware properties at runtime. */
	unsigned flags;
# define NIC_FLAG_NO_INTERRUPT          0x01 /* to be set at init time only */
# define NIC_FLAG_TRY_MSI               0x02
# define NIC_FLAG_MSI                   0x04
# define NIC_FLAG_OS_IRQ_EN             0x08
# define NIC_FLAG_10G                   0x10

	unsigned mtu;		/*!< MAC MTU (includes MAC hdr) */

	/* hardware resources */

	/*! I/O address of the start of the bar */
	volatile char __iomem *bar_ioaddr;

	/*! Bar number of control aperture. */
	unsigned ctr_ap_bar;
	/*! Length of control aperture in bytes. */
	unsigned ctr_ap_bytes;

	uint8_t mac_addr[ETH_ALEN];	/*!< mac address  */

	/*! EtherFabric Functional Units -- functions */
	const struct efhw_func_ops *efhw_func;

	/*! This lock protects a number of misc NIC resources.  It should
	 * only be used for things that can be at the bottom of the lock
	 * order.  ie. You mustn't attempt to grab any other lock while
	 * holding this one.
	 */
	spinlock_t *reg_lock;
	spinlock_t the_reg_lock;

	int buf_commit_outstanding;	/*!< outstanding buffer commits */

	/*! interrupt callbacks (hard-irq) */
	void (*irq_handler) (struct efhw_nic *, int unit);

	/*! event queues per driver */
	struct efhw_keventq interrupting_evq;

/* for marking when we are not using an IRQ unit
      - 0 is a valid offset to an IRQ unit on EF1! */
#define EFHW_IRQ_UNIT_UNUSED  0xffff
	/*! interrupt unit in use for the interrupting event queue  */
	unsigned int irq_unit;

	struct efhw_keventq non_interrupting_evq;

	/*! Bit masks of the sizes of event queues and dma queues supported
	 * by the nic. */
	unsigned evq_sizes;
	unsigned rxq_sizes;
	unsigned txq_sizes;

	/* Size of filter tables. */
	unsigned ip_filter_tbl_size;
	unsigned mac_filter_tbl_size;
	unsigned tx_ip_filter_tbl_size;
	unsigned tx_mac_filter_tbl_size;

	/* Number of filters currently used in each filter table */
	unsigned ip_filter_tbl_used;
	unsigned mac_filter_tbl_used;
	unsigned tx_ip_filter_tbl_used;
	unsigned tx_mac_filter_tbl_used;

	/* Dynamically allocated filter state. */
	uint8_t *filter_in_use;
	struct efhw_filter_spec *filter_spec_cache;

	/* Currently required and maximum filter table search depths. */
	struct efhw_filter_depth tcp_full_srch;
	struct efhw_filter_depth tcp_wild_srch;
	struct efhw_filter_depth udp_full_srch;
	struct efhw_filter_depth udp_wild_srch;
	struct efhw_filter_depth mac_full_srch;
	struct efhw_filter_depth mac_wild_srch;
	struct efhw_filter_depth tx_tcp_full_srch;
	struct efhw_filter_depth tx_tcp_wild_srch;
	struct efhw_filter_depth tx_udp_full_srch;
	struct efhw_filter_depth tx_udp_wild_srch;
	struct efhw_filter_depth tx_mac_full_srch;
	struct efhw_filter_depth tx_mac_wild_srch;

	/* Number of event queues, DMA queues and timers. */
	unsigned num_evqs;
	unsigned num_dmaqs;
	unsigned num_timers;
};


#define EFHW_KVA(nic)       ((nic)->bar_ioaddr)

static inline int efhw_in_fpga(struct efhw_nic *nic) {
	return nic->devtype.in_fpga;
}

static inline int efhw_in_cosim(struct efhw_nic *nic) {
	return nic->devtype.in_cosim;
}

#endif /* __CI_EFHW_EFHW_TYPES_H__ */
