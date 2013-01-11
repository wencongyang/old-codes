/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2009 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#ifndef EFX_KERNEL_COMPAT_H
#define EFX_KERNEL_COMPAT_H

#include <linux/version.h>
#include <linux/autoconf.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/pci.h>
#include <linux/workqueue.h>
#include <linux/moduleparam.h>
#include <linux/interrupt.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/rtnetlink.h>
#include <linux/i2c.h>
#include <linux/sysfs.h>
#include <linux/stringify.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/wait.h>

/**************************************************************************
 *
 * Autoconf compatability
 *
 **************************************************************************/

#include "autocompat.h"

/**************************************************************************
 *
 * Version/config/architecture compatability.
 *
 **************************************************************************
 *
 * The preferred kernel compatability mechanism is through the autoconf
 * layer above. For compatability fixes that are safe to apply to any kernel
 * version, or those that are impossible (or slow) to determine in autconf,
 * it is acceptable to have a version check here.
 */

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,5)
	#error "This kernel version is now unsupported"
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,12)
	#define EFX_HAVE_MSIX_TABLE_RESERVED yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,13)
	#define EFX_HAVE_WORKQUEUE_NAME_LIMIT yes
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,15) || defined(CONFIG_HUGETLB_PAGE)
	#define EFX_USE_COMPOUND_PAGES yes
#endif
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,16) && defined(EFX_USE_COMPOUND_PAGES)
	#define EFX_NEED_COMPOUND_PAGE_FIX
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,17)
	#define EFX_NEED_UNREGISTER_NETDEVICE_NOTIFIER_FIX yes
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,19)
	#define EFX_USE_GSO_SIZE_FOR_MSS yes
#else
	#define EFX_HAVE_NONCONST_ETHTOOL_OPS yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	#define EFX_USE_FASTCALL yes
#endif

/* debugfs only supports sym-links from 2.6.21 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,21) && defined(CONFIG_DEBUG_FS)
	#define EFX_USE_DEBUGFS yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,24)
	#define EFX_NEED_BONDING_HACKS yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,28)
	#define EFX_NEED_LM87_DRIVER yes
	#define EFX_NEED_LM90_DRIVER yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	#define EFX_USE_NET_DEVICE_LAST_RX yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,31)
	#define EFX_USE_NET_DEVICE_TRANS_START yes
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,33)
	#ifdef EFX_HAVE_LINUX_MDIO_H
		/* mdio module has some bugs in pause frame advertising */
		#define EFX_NEED_MDIO45_FLOW_CONTROL_HACKS yes
	#endif
#endif

#ifdef CONFIG_PPC64
	/* __raw_writel and friends are broken on ppc64 */
	#define EFX_NEED_RAW_READ_AND_WRITE_FIX yes
#endif

/**************************************************************************
 *
 * Definitions of missing constants, types, functions and macros
 *
 **************************************************************************
 *
 */

#ifndef spin_trylock_irqsave
	#define spin_trylock_irqsave(lock, flags)	\
	({						\
		local_irq_save(flags);			\
		spin_trylock(lock) ?			\
		1 : ({local_irq_restore(flags); 0;});	\
	})
#endif

#ifndef raw_smp_processor_id
	#define raw_smp_processor_id() (current_thread_info()->cpu)
#endif

#ifndef NETIF_F_GEN_CSUM
	#define NETIF_F_GEN_CSUM (NETIF_F_NO_CSUM | NETIF_F_HW_CSUM)
#endif
#ifndef NETIF_F_V4_CSUM
	#define NETIF_F_V4_CSUM (NETIF_F_GEN_CSUM | NETIF_F_IP_CSUM)
#endif
#ifndef NETIF_F_V6_CSUM
	#define NETIF_F_V6_CSUM  NETIF_F_GEN_CSUM
#endif
#ifndef NETIF_F_ALL_CSUM
	#define NETIF_F_ALL_CSUM (NETIF_F_V4_CSUM | NETIF_F_V6_CSUM)
#endif

/* Cope with small changes in PCI constants between minor kernel revisions */
#if PCI_X_STATUS != 4
	#undef PCI_X_STATUS
	#define PCI_X_STATUS 4
	#undef PCI_X_STATUS_MAX_SPLIT
	#define PCI_X_STATUS_MAX_SPLIT 0x03800000
#endif

#ifndef __GFP_COMP
	#define __GFP_COMP 0
#endif

#ifndef __iomem
	#define __iomem
#endif

#ifndef NET_IP_ALIGN
	#define NET_IP_ALIGN 2
#endif

#ifndef PCI_EXP_FLAGS
	#define PCI_EXP_FLAGS		2	/* Capabilities register */
	#define PCI_EXP_FLAGS_TYPE	0x00f0	/* Device/Port type */
	#define  PCI_EXP_TYPE_ENDPOINT	0x0	/* Express Endpoint */
	#define  PCI_EXP_TYPE_LEG_END	0x1	/* Legacy Endpoint */
	#define  PCI_EXP_TYPE_ROOT_PORT 0x4	/* Root Port */
#endif

#ifndef PCI_EXP_DEVCAP
	#define PCI_EXP_DEVCAP		4	/* Device capabilities */
	#define  PCI_EXP_DEVCAP_PAYLOAD	0x07	/* Max_Payload_Size */
	#define  PCI_EXP_DEVCAP_PWR_VAL	0x3fc0000 /* Slot Power Limit Value */
	#define  PCI_EXP_DEVCAP_PWR_SCL	0xc000000 /* Slot Power Limit Scale */
#endif

#ifndef PCI_EXP_DEVCTL
	#define PCI_EXP_DEVCTL		8	/* Device Control */
	#define  PCI_EXP_DEVCTL_PAYLOAD	0x00e0	/* Max_Payload_Size */
	#define  PCI_EXP_DEVCTL_READRQ	0x7000	/* Max_Read_Request_Size */
#endif

#ifndef PCI_EXP_LNKSTA
	#define PCI_EXP_LNKSTA		18	/* Link Status */
#endif
#ifndef PCI_EXP_LNKSTA_CLS
	#define  PCI_EXP_LNKSTA_CLS	0x000f	/* Current Link Speed */
#endif
#ifndef PCI_EXP_LNKSTA_NLW
	#define  PCI_EXP_LNKSTA_NLW	0x03f0	/* Nogotiated Link Width */
#endif

#ifndef NETDEV_TX_OK
	#define NETDEV_TX_OK 0
#endif

#ifndef NETDEV_TX_BUSY
	#define NETDEV_TX_BUSY 1
#endif

#ifndef __force
	#define __force
#endif

#if ! defined(for_each_cpu_mask) && ! defined(CONFIG_SMP)
	#define for_each_cpu_mask(cpu, mask)            \
		for ((cpu) = 0; (cpu) < 1; (cpu)++, (void)mask)
#endif

#ifndef IRQF_PROBE_SHARED
	#ifdef SA_PROBEIRQ
		#define IRQF_PROBE_SHARED  SA_PROBEIRQ
	#else
		#define IRQF_PROBE_SHARED  0
	#endif
#endif

#ifndef IRQF_SHARED
	#define IRQF_SHARED	   SA_SHIRQ
#endif

#ifndef mmiowb
	#if defined(__i386__) || defined(__x86_64__)
		#define mmiowb()
	#elif defined(__ia64__)
		#ifndef ia64_mfa
			#define ia64_mfa() asm volatile ("mf.a" ::: "memory")
		#endif
		#define mmiowb ia64_mfa
	#else
		#error "Need definition for mmiowb()"
	#endif
#endif

#ifndef CHECKSUM_PARTIAL
	#define CHECKSUM_PARTIAL CHECKSUM_HW
#endif

#ifndef DMA_BIT_MASK
	#define DMA_BIT_MASK(n) (((n) == 64) ? ~0ULL : ((1ULL<<(n))-1))
#endif

#if defined(__GNUC__) && !defined(inline)
	#define inline inline __attribute__ ((always_inline))
#endif

#if defined(__GNUC__) && !defined(__packed)
	#define __packed __attribute__((packed))
#endif

#ifndef DIV_ROUND_UP
	#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#endif

#ifndef __ATTR
	#define __ATTR(_name,_mode,_show,_store) {			\
		.attr = {.name = __stringify(_name), .mode = _mode },	\
		.show   = _show,					\
		.store  = _store,					\
	}
#endif

#ifndef DEVICE_ATTR
	#define DEVICE_ATTR(_name, _mode, _show, _store)		\
		struct device_attribute dev_attr_ ## _name =		\
			__ATTR(_name, _mode, _show, _store)
#endif

#ifndef to_i2c_adapter
	#define to_i2c_adapter dev_to_i2c_adapter
#endif

#if defined(CONFIG_X86) && !defined(CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS)
	#define CONFIG_HAVE_EFFICIENT_UNALIGNED_ACCESS
#endif

#ifndef BUILD_BUG_ON_ZERO
	#define BUILD_BUG_ON_ZERO(e) (sizeof(char[1 - 2 * !!(e)]) - 1)
#endif

#ifndef __bitwise
	#define __bitwise
#endif

#ifdef EFX_NEED_ATOMIC_CMPXCHG
	#define atomic_cmpxchg(v, old, new) ((int)cmpxchg(&((v)->counter), old, new))
#endif

/**************************************************************************/

#ifdef EFX_NEED_IRQ_HANDLER_T
	typedef irqreturn_t (*irq_handler_t)(int, void *, struct pt_regs *);
#endif

/* linux_mdio.h needs this */
#ifdef EFX_NEED_BOOL
	typedef _Bool bool;
	enum { false, true };
#endif

#ifdef EFX_HAVE_LINUX_MDIO_H
	#include <linux/mdio.h>
#else
	#include "linux_mdio.h"
#endif

#ifdef EFX_NEED_MII_CONSTANTS
	#define BMCR_SPEED1000		0x0040
	#define ADVERTISE_PAUSE_ASYM	0x0800
	#define ADVERTISE_PAUSE_CAP	0x0400
#endif

#ifdef EFX_NEED_ETHTOOL_CONSTANTS
	#define ADVERTISED_Pause	(1 << 13)
	#define ADVERTISED_Asym_Pause	(1 << 14)
#endif

#ifndef EFX_HAVE_ETHTOOL_RESET
	enum ethtool_reset_flags {
		/* These flags represent components dedicated to the interface
		 * the command is addressed to.  Shift any flag left by
		 * ETH_RESET_SHARED_SHIFT to reset a shared component of the
		 * same type.
		 */
	  	ETH_RESET_MGMT		= 1 << 0,	/* Management processor */
		ETH_RESET_IRQ		= 1 << 1,	/* Interrupt requester */
		ETH_RESET_DMA		= 1 << 2,	/* DMA engine */
		ETH_RESET_FILTER	= 1 << 3,	/* Filtering/flow direction */
		ETH_RESET_OFFLOAD	= 1 << 4,	/* Protocol offload */
		ETH_RESET_MAC		= 1 << 5,	/* Media access controller */
		ETH_RESET_PHY		= 1 << 6,	/* Transceiver/PHY */
		ETH_RESET_RAM		= 1 << 7,	/* RAM shared between
							 * multiple components */

		ETH_RESET_DEDICATED	= 0x0000ffff,	/* All components dedicated to
							 * this interface */
		ETH_RESET_ALL		= 0xffffffff,	/* All components used by this
							 * interface, even if shared */
	};
	#define ETH_RESET_SHARED_SHIFT	16
#endif

#ifndef FLOW_CTRL_TX
	#define FLOW_CTRL_TX		0x01
	#define FLOW_CTRL_RX		0x02
#endif

#ifdef EFX_NEED_MII_RESOLVE_FLOWCTRL_FDX
	/**
	 * mii_resolve_flowctrl_fdx
	 * @lcladv: value of MII ADVERTISE register
	 * @rmtadv: value of MII LPA register
	 *
	 * Resolve full duplex flow control as per IEEE 802.3-2005 table 28B-3
	 */
	static inline u8 mii_resolve_flowctrl_fdx(u16 lcladv, u16 rmtadv)
	{
		u8 cap = 0;

		if (lcladv & rmtadv & ADVERTISE_PAUSE_CAP) {
			cap = FLOW_CTRL_TX | FLOW_CTRL_RX;
		} else if (lcladv & rmtadv & ADVERTISE_PAUSE_ASYM) {
			if (lcladv & ADVERTISE_PAUSE_CAP)
				cap = FLOW_CTRL_RX;
			else if (rmtadv & ADVERTISE_PAUSE_CAP)
				cap = FLOW_CTRL_TX;
		}

		return cap;
	}
#endif

#ifdef EFX_NEED_MII_ADVERTISE_FLOWCTRL
	/**
	 * mii_advertise_flowctrl - get flow control advertisement flags
	 * @cap: Flow control capabilities (FLOW_CTRL_RX, FLOW_CTRL_TX or both)
	 */
	static inline u16 mii_advertise_flowctrl(int cap)
	{
		u16 adv = 0;

		if (cap & FLOW_CTRL_RX)
			adv = ADVERTISE_PAUSE_CAP | ADVERTISE_PAUSE_ASYM;
		if (cap & FLOW_CTRL_TX)
			adv ^= ADVERTISE_PAUSE_ASYM;

		return adv;
	}
#endif

#ifndef PORT_OTHER
	#define PORT_OTHER		0xff
#endif

#ifndef SUPPORTED_Pause
	#define SUPPORTED_Pause			(1 << 13)
	#define SUPPORTED_Asym_Pause		(1 << 14)
#endif

#ifndef SUPPORTED_Backplane
	#define SUPPORTED_Backplane		(1 << 16)
	#define SUPPORTED_1000baseKX_Full	(1 << 17)
	#define SUPPORTED_10000baseKX4_Full	(1 << 18)
	#define SUPPORTED_10000baseKR_Full	(1 << 19)
	#define SUPPORTED_10000baseR_FEC	(1 << 20)
#endif

#ifdef EFX_NEED_SKB_HEADER_MACROS
	#define skb_mac_header(skb)	((skb)->mac.raw)
	#define skb_network_header(skb) ((skb)->nh.raw)
	#define skb_tail_pointer(skb)   ((skb)->tail)
#endif

#ifdef EFX_NEED_ETH_HDR
	#define eth_hdr(skb)		((struct ethhdr *)skb_mac_header(skb))
#endif

#ifdef EFX_NEED_TCP_HDR
	#define tcp_hdr(skb)		((skb)->h.th)
#endif

#ifdef EFX_NEED_IP_HDR
	#define ip_hdr(skb)		((skb)->nh.iph)
#endif

#ifdef EFX_NEED_IPV6_HDR
	#define ipv6_hdr(skb)		((skb)->nh.ipv6h)
#endif

#ifdef EFX_NEED_RAW_READ_AND_WRITE_FIX
	#include <asm/io.h>
	static inline void
	efx_raw_writeb(u8 value, volatile void __iomem *addr)
	{
		writeb(value, addr);
	}
	static inline void
	efx_raw_writew(u16 value, volatile void __iomem *addr)
	{
		writew(le16_to_cpu(value), addr);
	}
	static inline void
	efx_raw_writel(u32 value, volatile void __iomem *addr)
	{
		writel(le32_to_cpu(value), addr);
	}
	static inline void
	efx_raw_writeq(u64 value, volatile void __iomem *addr)
	{
		writeq(le64_to_cpu(value), addr);
	}
	static inline u8
	efx_raw_readb(const volatile void __iomem *addr)
	{
		return readb(addr);
	}
	static inline u16
	efx_raw_readw(const volatile void __iomem *addr)
	{
		return cpu_to_le16(readw(addr));
	}
	static inline u32
	efx_raw_readl(const volatile void __iomem *addr)
	{
		return cpu_to_le32(readl(addr));
	}
	static inline u64
	efx_raw_readq(const volatile void __iomem *addr)
	{
		return cpu_to_le64(readq(addr));
	}

	#undef __raw_writeb
	#undef __raw_writew
	#undef __raw_writel
	#undef __raw_writeq
	#undef __raw_readb
	#undef __raw_readw
	#undef __raw_readl
	#undef __raw_readq
	#define __raw_writeb efx_raw_writeb
	#define __raw_writew efx_raw_writew
	#define __raw_writel efx_raw_writel
	#define __raw_writeq efx_raw_writeq
	#define __raw_readb efx_raw_readb
	#define __raw_readw efx_raw_readw
	#define __raw_readl efx_raw_readl
	#define __raw_readq efx_raw_readq
#endif

#ifdef EFX_NEED_SCHEDULE_TIMEOUT_INTERRUPTIBLE
	static inline signed long
	schedule_timeout_interruptible(signed long timeout)
	{
		set_current_state(TASK_INTERRUPTIBLE);
		return schedule_timeout(timeout);
	}
#endif

#ifdef EFX_NEED_SCHEDULE_TIMEOUT_UNINTERRUPTIBLE
	static inline signed long
	schedule_timeout_uninterruptible(signed long timeout)
	{
		set_current_state(TASK_UNINTERRUPTIBLE);
		return schedule_timeout(timeout);
	}
#endif

#ifdef EFX_NEED_KZALLOC
	static inline void *kzalloc(size_t size, int flags)
	{
		void *buf = kmalloc(size, flags);
		if (buf)
			memset(buf, 0,size);
		return buf;
	}
#endif

#ifdef EFX_NEED_SETUP_TIMER
	static inline void setup_timer(struct timer_list * timer,
				       void (*function)(unsigned long),
				       unsigned long data)
	{
		timer->function = function;
		timer->data = data;
		init_timer(timer);
	}
#endif

#ifdef EFX_NEED_MUTEX
	#define EFX_DEFINE_MUTEX(x) DECLARE_MUTEX(x)
	#undef DEFINE_MUTEX
	#define DEFINE_MUTEX EFX_DEFINE_MUTEX

	#define efx_mutex semaphore
	#undef mutex
	#define mutex efx_mutex

	#define efx_mutex_init(x) init_MUTEX(x)
	#undef mutex_init
	#define mutex_init efx_mutex_init

	#define efx_mutex_destroy(x) do { } while(0)
	#undef mutex_destroy
	#define mutex_destroy efx_mutex_destroy

	#define efx_mutex_lock(x) down(x)
	#undef mutex_lock
	#define mutex_lock efx_mutex_lock

	#define efx_mutex_lock_interruptible(x) down_interruptible(x)
	#undef mutex_lock_interruptible
	#define mutex_lock_interruptible efx_mutex_lock_interruptible

	#define efx_mutex_unlock(x) up(x)
	#undef mutex_unlock
	#define mutex_unlock efx_mutex_unlock

	#define efx_mutex_trylock(x) (!down_trylock(x))
	#undef mutex_trylock
	#define mutex_trylock efx_mutex_trylock

	static inline int efx_mutex_is_locked(struct efx_mutex *m)
	{
		/* NB. This is quite inefficient, but it's the best we
		 * can do with the semaphore API. */
		if ( down_trylock(m) )
			return 1;
		/* Undo the effect of down_trylock. */
		up(m);
		return 0;
	}
	#undef mutex_is_locked
	#define mutex_is_locked efx_mutex_is_locked
#endif

#ifndef NETIF_F_GSO
	#define efx_gso_size tso_size
	#undef gso_size
	#define gso_size efx_gso_size
	#define efx_gso_segs tso_segs
	#undef gso_segs
	#define gso_segs efx_gso_segs
#endif

#ifdef EFX_NEED_NETDEV_ALLOC_SKB
	#ifndef NET_SKB_PAD
		#define NET_SKB_PAD 16
	#endif

	static inline
	struct sk_buff *netdev_alloc_skb(struct net_device *dev,
					 unsigned int length)
	{
		struct sk_buff *skb = alloc_skb(length + NET_SKB_PAD,
						GFP_ATOMIC | __GFP_COLD);
		if (likely(skb)) {
			skb_reserve(skb, NET_SKB_PAD);
			skb->dev = dev;
		}
		return skb;
	}
#endif

#ifdef EFX_NEED_NETDEV_TX_T
	typedef int netdev_tx_t;
#endif

#ifdef EFX_HAVE_NONCONST_ETHTOOL_OPS
	#undef SET_ETHTOOL_OPS
	#define SET_ETHTOOL_OPS(netdev, ops)				\
		((netdev)->ethtool_ops = (struct ethtool_ops *)(ops))
#endif

#ifdef EFX_NEED_RTNL_TRYLOCK
	static inline int rtnl_trylock(void) {
		return !rtnl_shlock_nowait();
	}
#endif

#ifdef EFX_NEED_NETIF_TX_LOCK
	static inline void netif_tx_lock(struct net_device *dev)
	{
		spin_lock(&dev->xmit_lock);
		dev->xmit_lock_owner = smp_processor_id();
	}
	static inline void netif_tx_lock_bh(struct net_device *dev)
	{
		spin_lock_bh(&dev->xmit_lock);
		dev->xmit_lock_owner = smp_processor_id();
	}
	static inline void netif_tx_unlock_bh(struct net_device *dev)
	{
		dev->xmit_lock_owner = -1;
		spin_unlock_bh(&dev->xmit_lock);
	}
	static inline void netif_tx_unlock(struct net_device *dev)
	{
		dev->xmit_lock_owner = -1;
		spin_unlock(&dev->xmit_lock);
	}
#endif

#ifdef EFX_NEED_NETIF_ADDR_LOCK
	static inline void netif_addr_lock(struct net_device *dev)
	{
		netif_tx_lock(dev);
	}
	static inline void netif_addr_lock_bh(struct net_device *dev)
	{
		netif_tx_lock_bh(dev);
	}
	static inline void netif_addr_unlock_bh(struct net_device *dev)
	{
		netif_tx_unlock_bh(dev);
	}
	static inline void netif_addr_unlock(struct net_device *dev)
	{
		netif_tx_unlock(dev);
	}
#endif

#ifdef EFX_NEED_DEV_GET_STATS
	static inline const struct net_device_stats *
	dev_get_stats(struct net_device *dev)
	{
		return dev->get_stats(dev);
	}
#endif

#ifdef EFX_HAVE_OLD_IP_FAST_CSUM
	#define ip_fast_csum(iph, ihl) ip_fast_csum((unsigned char *)iph, ihl)
#endif

#ifdef EFX_HAVE_OLD_CSUM
	typedef u16 __sum16;
	typedef u32 __wsum;
	#define csum_unfold(x) ((__force __wsum) x)
#endif

#ifdef EFX_NEED_HEX_DUMP
	enum {
		DUMP_PREFIX_NONE,
		DUMP_PREFIX_ADDRESS,
		DUMP_PREFIX_OFFSET
	};
#endif

#ifndef DECLARE_MAC_BUF
	#define DECLARE_MAC_BUF(var) char var[18] __attribute__((unused))
#endif

#ifdef EFX_NEED_GFP_T
	typedef unsigned int gfp_t;
#endif

#ifdef EFX_NEED_SAFE_LISTS
	#define list_for_each_entry_safe_reverse(pos, n, head, member)	     \
		for (pos = list_entry((head)->prev, typeof(*pos), member),   \
		     n = list_entry(pos->member.prev, typeof(*pos), member); \
		     &pos->member != (head);				     \
		     pos = n,						     \
		     n = list_entry(n->member.prev, typeof(*n), member))
#endif

#ifdef EFX_NEED_DEV_NOTICE
	#define dev_notice dev_warn
#endif

#ifdef EFX_NEED_IF_MII
	#include <linux/mii.h>
	static inline struct mii_ioctl_data *efx_if_mii ( struct ifreq *rq ) {
		return ( struct mii_ioctl_data * ) &rq->ifr_ifru;
	}
	#undef if_mii
	#define if_mii efx_if_mii
#endif

#ifdef EFX_NEED_MTD_ERASE_CALLBACK
	#include <linux/mtd/mtd.h>
	static inline void efx_mtd_erase_callback(struct erase_info *instr) {
		if ( instr->callback )
			instr->callback ( instr );
	}
	#undef mtd_erase_callback
	#define mtd_erase_callback efx_mtd_erase_callback
#endif

#ifdef EFX_NEED_DUMMY_PCI_DISABLE_MSI
	#include <linux/pci.h>
	static inline void dummy_pci_disable_msi ( struct pci_dev *dev ) {
		/* Do nothing */
	}
	#undef pci_disable_msi
	#define pci_disable_msi dummy_pci_disable_msi
#endif

#ifdef EFX_NEED_DUMMY_MSIX
	struct msix_entry {
		u16 	vector;	/* kernel uses to write allocated vector */
		u16	entry;	/* driver uses to specify entry, OS writes */
	};
	static inline int pci_enable_msix(struct pci_dev* dev,
					  struct msix_entry *entries, int nvec)
		{return -1;}
	static inline void pci_disable_msix(struct pci_dev *dev) { /* Do nothing */}
#endif

#ifdef EFX_NEED_BYTEORDER_TYPES
	typedef __u16 __be16;
	typedef __u32 __be32;
	typedef __u64 __be64;
	typedef __u16 __le16;
	typedef __u32 __le32;
	typedef __u64 __le64;
#endif

#ifdef EFX_NEED_RESOURCE_SIZE_T
	typedef unsigned long resource_size_t;
#endif

#ifdef EFX_USE_I2C_LEGACY
	struct i2c_board_info {
		char type[I2C_NAME_SIZE];
		unsigned short flags;
		unsigned short addr;
		void *platform_data;
		int irq;
	};
	#define I2C_BOARD_INFO(dev_type, dev_addr) \
		.type = (dev_type), .addr = (dev_addr)
	struct i2c_client *
	i2c_new_device(struct i2c_adapter *adap, struct i2c_board_info *info);
	struct i2c_client *
	i2c_new_probed_device(struct i2c_adapter *adap,
			      struct i2c_board_info *info,
			      const unsigned short *addr_list);
	void i2c_unregister_device(struct i2c_client *);
	struct i2c_device_id;
#endif

#ifdef EFX_NEED_I2C_NEW_DUMMY
	extern struct i2c_driver efx_i2c_dummy_driver;
	struct i2c_client *
	efx_i2c_new_dummy(struct i2c_adapter *adap, u16 address);
	#undef i2c_new_dummy
	#define i2c_new_dummy efx_i2c_new_dummy
#endif

#ifdef EFX_HAVE_OLD_I2C_NEW_DUMMY
	static inline struct i2c_client *
	efx_i2c_new_dummy(struct i2c_adapter *adap, u16 address)
	{
		return i2c_new_dummy(adap, address, "dummy");
	}
	#undef i2c_new_dummy
	#define i2c_new_dummy efx_i2c_new_dummy
#endif

#ifdef EFX_NEED_I2C_LOCK_ADAPTER
	#ifdef EFX_USE_I2C_BUS_SEMAPHORE
		static inline void i2c_lock_adapter(struct i2c_adapter *adap)
		{
			down(&adap->bus_lock);
		}
		static inline void i2c_unlock_adapter(struct i2c_adapter *adap)
		{
			up(&adap->bus_lock);
		}
	#else
		static inline void i2c_lock_adapter(struct i2c_adapter *adap)
		{
			mutex_lock(&adap->bus_lock);
		}
		static inline void i2c_unlock_adapter(struct i2c_adapter *adap)
		{
			mutex_unlock(&adap->bus_lock);
		}
	#endif
#endif

#ifdef EFX_HAVE_OLD_PCI_DMA_MAPPING_ERROR
	static inline int
	efx_pci_dma_mapping_error(struct pci_dev *dev, dma_addr_t dma_addr)
	{
        	return pci_dma_mapping_error(dma_addr);
	}
	#undef pci_dma_mapping_error
	#define pci_dma_mapping_error efx_pci_dma_mapping_error
#endif

#ifdef EFX_NEED_FOR_EACH_PCI_DEV
	#define for_each_pci_dev(d)				\
		while ((d = pci_get_device(PCI_ANY_ID,		\
			PCI_ANY_ID, d)) != NULL)
#endif

#ifdef EFX_NEED_LM87_DRIVER
#ifdef EFX_HAVE_OLD_I2C_DRIVER_PROBE
int efx_lm87_probe(struct i2c_client *client);
#else
int efx_lm87_probe(struct i2c_client *client, const struct i2c_device_id *);
#endif
extern struct i2c_driver efx_lm87_driver;
#endif

#ifdef EFX_NEED_LM90_DRIVER
#ifdef EFX_HAVE_OLD_I2C_DRIVER_PROBE
int efx_lm90_probe(struct i2c_client *client);
#else
int efx_lm90_probe(struct i2c_client *client, const struct i2c_device_id *);
#endif
extern struct i2c_driver efx_lm90_driver;
#endif

#ifdef EFX_NEED_WAIT_EVENT_TIMEOUT
#define __wait_event_timeout(wq, condition, ret)                        \
do {                                                                    \
        DEFINE_WAIT(__wait);                                            \
                                                                        \
        for (;;) {                                                      \
                prepare_to_wait(&wq, &__wait, TASK_UNINTERRUPTIBLE);    \
                if (condition)                                          \
                        break;                                          \
                ret = schedule_timeout(ret);                            \
                if (!ret)                                               \
                        break;                                          \
        }                                                               \
        finish_wait(&wq, &__wait);                                      \
} while (0)

/**
 * wait_event_timeout - sleep until a condition gets true or a timeout elapses
 * @wq: the waitqueue to wait on
 * @condition: a C expression for the event to wait for
 * @timeout: timeout, in jiffies
 *
 * The process is put to sleep (TASK_UNINTERRUPTIBLE) until the
 * @condition evaluates to true. The @condition is checked each time
 * the waitqueue @wq is woken up.
 *
 * wake_up() has to be called after changing any variable that could
 * change the result of the wait condition.
 *
 * The function returns 0 if the @timeout elapsed, and the remaining
 * jiffies if the condition evaluated to true before the timeout elapsed.
 */
#define wait_event_timeout(wq, condition, timeout)                      \
({                                                                      \
        long __ret = timeout;                                           \
        if (!(condition))                                               \
                __wait_event_timeout(wq, condition, __ret);             \
        __ret;                                                          \
})
#endif

/**************************************************************************
 *
 * Missing functions provided by kernel_compat.c
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_RANDOM_ETHER_ADDR
	extern void efx_random_ether_addr(uint8_t *addr);
	#ifndef EFX_IN_KCOMPAT_C
		#undef random_ether_addr
		#define random_ether_addr efx_random_ether_addr
	#endif
#endif

#ifdef EFX_NEED_UNREGISTER_NETDEVICE_NOTIFIER_FIX
	extern int efx_unregister_netdevice_notifier(struct notifier_block *nb);
	#ifndef EFX_IN_KCOMPAT_C
		#undef unregister_netdevice_notifier
		#define unregister_netdevice_notifier \
				efx_unregister_netdevice_notifier
	#endif
#endif

#ifdef EFX_NEED_PRINT_MAC
	extern char *print_mac(char *buf, const u8 *addr);
#endif

#ifdef EFX_NEED_COMPOUND_PAGE_FIX
	extern void efx_compound_page_destructor(struct page *page);
#endif

#ifdef EFX_NEED_HEX_DUMP
	extern void
	print_hex_dump(const char *level, const char *prefix_str,
		       int prefix_type, int rowsize, int groupsize,
		       const void *buf, size_t len, int ascii);
#endif

#ifdef EFX_NEED_PCI_CLEAR_MASTER
	extern void pci_clear_master(struct pci_dev *dev);
#endif

#ifdef EFX_NEED_PCI_WAKE_FROM_D3
	extern int pci_wake_from_d3(struct pci_dev *dev, bool enable);
#endif

#ifdef EFX_NEED_MSECS_TO_JIFFIES
	extern unsigned long msecs_to_jiffies(const unsigned int m);
#endif

#ifdef EFX_NEED_MSLEEP
	extern void msleep(unsigned int msecs);
#endif

#ifdef EFX_NEED_SSLEEP
	static inline void ssleep(unsigned int seconds)
	{
		msleep(seconds * 1000);
	}
#endif

#ifdef EFX_NEED_MDELAY
	#include <linux/delay.h>
	#undef mdelay
	#define mdelay(_n)				\
		do {					\
			unsigned long __ms = _n;	\
			while (__ms--) udelay(1000);	\
		} while (0);
#endif

#ifdef EFX_NEED_UNMASK_MSIX_VECTORS
	extern void efx_unmask_msix_vectors(struct pci_dev *dev);
#endif

/**************************************************************************
 *
 * Wrappers to fix bugs and parameter changes
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_PCI_SAVE_RESTORE_WRAPPERS
	#define pci_save_state(_dev)					\
		pci_save_state(_dev, (_dev)->saved_config_space)

	#define pci_restore_state(_dev)					\
		pci_restore_state(_dev, (_dev)->saved_config_space)
#endif

#ifdef EFX_NEED_PCI_MATCH_ID
	#define pci_match_id pci_match_device
#endif

#ifdef EFX_NEED_WORK_API_WRAPPERS
	#define delayed_work work_struct
	#define INIT_DELAYED_WORK INIT_WORK

	/**
	 * The old and new work-function prototypes just differ
	 * in the type of the pointer returned, so it's safe
	 * to cast between the prototypes.
	 */
	typedef void (*efx_old_work_func_t)(void *p);

	#undef INIT_WORK
	#define INIT_WORK(_work, _func)					\
		do {							\
			INIT_LIST_HEAD(&(_work)->entry);		\
			(_work)->pending = 0;				\
			PREPARE_WORK((_work),				\
				     (efx_old_work_func_t) (_func),	\
				     (_work));				\
	                init_timer(&(_work)->timer);                    \
		} while (0)
#endif

#if defined(EFX_HAVE_OLD_NAPI)
	#define napi_str napi_dev[0]

	static inline void netif_napi_add(struct net_device *dev,
					  struct net_device *dummy,
					  int (*poll) (struct net_device *,
						       int *),
					  int weight)
	{
		dev->weight = weight;
		dev->poll = poll;
	}
	static inline void netif_napi_del(struct net_device *dev) {}

	#define napi_enable netif_poll_enable
	#define napi_disable netif_poll_disable
	#define napi_complete netif_rx_complete

	static inline void napi_schedule(struct net_device *dev)
	{
		if (!test_and_set_bit(__LINK_STATE_RX_SCHED, &dev->state))
			__netif_rx_schedule(dev);
	}
#elif defined(EFX_NEED_NETIF_NAPI_DEL)
	static inline void netif_napi_del(struct napi_struct *napi)
	{
	#ifdef CONFIG_NETPOLL
        	list_del(&napi->dev_list);
	#endif
	}
#endif

#ifdef EFX_NEED_COMPOUND_PAGE_FIX
	static inline
	struct page *efx_alloc_pages(gfp_t flags, unsigned int order)
	{
		struct page *p = alloc_pages(flags, order);
		if ((flags & __GFP_COMP) && (p != NULL) && (order > 0))
			p[1].mapping = (void *)efx_compound_page_destructor;
		return p;
	}
	#undef alloc_pages
	#define alloc_pages efx_alloc_pages

	static inline
	void efx_free_pages(struct page *p, unsigned int order)
	{
		if ((order > 0) && (page_count(p) == 1))
			p[1].mapping = NULL;
		__free_pages(p, order);
	}
	#define __free_pages efx_free_pages
#endif

#ifdef EFX_NEED_HEX_DUMP_CONST_FIX
	#define print_hex_dump(v,s,t,r,g,b,l,a) \
		print_hex_dump((v),(s),(t),(r),(g),(void*)(b),(l),(a))
#endif

#ifndef EFX_HAVE_HWMON_H
	static inline struct device *hwmon_device_register(struct device *dev)
	{
		return dev;
	}
	static inline void hwmon_device_unregister(struct device *cdev)
	{
	}
#endif

#ifdef EFX_NEED_HWMON_VID
	#include <linux/i2c-vid.h>
	static inline u8 efx_vid_which_vrm(void)
	{
		/* we don't use i2c on the cpu */
		return 0;
	}
	#define vid_which_vrm efx_vid_which_vrm
#endif

#ifdef EFX_HAVE_OLD_DEVICE_ATTRIBUTE
	/*
	 * show and store methods do not receive a pointer to the
	 * device_attribute.  We have to add wrapper functions.
	 */

	#undef DEVICE_ATTR
	#define DEVICE_ATTR(_name, _mode, _show, _store)		\
		/*static*/ ssize_t __##_name##_##show(struct device *dev, \
						      char *buf)	\
		{							\
			return _show(dev, NULL, buf);			\
		}							\
		static ssize_t __##_name##_##store(struct device *dev,	\
						   const char *buf,	\
						   size_t count)	\
		{							\
			ssize_t (*fn)(struct device *dev,		\
				      struct device_attribute *attr,	\
				      const char *buf,			\
				      size_t count) = _store;		\
			return fn(dev, NULL, buf, count);		\
		}							\
		static ssize_t __##_name##_##store(struct device *,	\
						   const char *, size_t) \
			__attribute__((unused));			\
		static struct device_attribute dev_attr_##_name =	\
			__ATTR(_name, _mode, __##_name##_##show,	\
			       __builtin_choose_expr			\
			       (__builtin_constant_p(_store) && _store == NULL, \
				NULL, __##_name##_##store))

	struct sensor_device_attribute {
		struct device_attribute dev_attr;
		int index;
	};

	#define SENSOR_ATTR(_name, _mode, _show, _store, _index)        \
	{ .dev_attr = __ATTR(_name, _mode, _show, _store),		\
	  .index = _index }

	#define SENSOR_DEVICE_ATTR(_name, _mode, _show,	\
				   _store, _index)			\
		/*static*/ ssize_t __##_name##_show_##_index(struct device *dev, \
							     char *buf)	\
		{							\
			struct sensor_device_attribute attr;		\
			attr.index = _index;				\
			return _show(dev, &attr.dev_attr, buf);		\
		}							\
		static ssize_t __##_name##_store_##_index(struct device *dev, \
							  const char *buf, \
							  size_t count)	\
		{							\
			ssize_t (*fn)(struct device *dev,		\
				      struct device_attribute *attr,	\
				      const char *buf,			\
				      size_t count) = _store;		\
			struct sensor_device_attribute attr;		\
			attr.index = _index;				\
			return fn(dev, &attr.dev_attr, buf, count);	\
		}							\
		static ssize_t __##_name##_store_##_index(struct device *, \
							  const char *, size_t) \
			__attribute__((unused));			\
		static struct sensor_device_attribute			\
			sensor_dev_attr_##_name =			\
			SENSOR_ATTR(_name, _mode,			\
				    __##_name##_show_##_index,		\
				    __builtin_choose_expr		\
				    (__builtin_constant_p(_store) && _store == NULL, \
				     NULL, __##_name##_store_##_index), \
				    _index)

	#define to_sensor_dev_attr(_dev_attr) \
		container_of(_dev_attr, struct sensor_device_attribute,	\
			     dev_attr)

#endif


#ifdef EFX_NEED_SCSI_SGLIST
	#include <scsi/scsi.h>
	#include <scsi/scsi_cmnd.h>
	#define scsi_sglist(sc)    ((struct scatterlist *)((sc)->request_buffer))
	#define scsi_bufflen(sc)   ((sc)->request_bufflen)
	#define scsi_sg_count(sc)  ((sc)->use_sg)
	static inline void scsi_set_resid(struct scsi_cmnd *sc, int resid)
	{
		sc->resid = resid;
	}
	static inline int scsi_get_resid(struct scsi_cmnd *sc)
	{
		return sc->resid;
	}
#endif


#ifdef EFX_NEED_SG_NEXT
	#define sg_page(sg) ((sg)->page)
	#define sg_next(sg) ((sg) + 1)
	#define for_each_sg(sglist, sg, nr, __i) \
	  for (__i = 0, sg = (sglist); __i < (nr); __i++, sg = sg_next(sg))
#endif

#ifdef EFX_NEED_WARN_ON
	#undef WARN_ON
	#define WARN_ON(condition) ({				\
		typeof(condition) __ret_warn_on = (condition);	\
		if (unlikely(__ret_warn_on)) {			\
			printk("BUG: warning at %s:%d/%s()\n",	\
			__FILE__, __LINE__, __FUNCTION__);	\
				dump_stack();			\
		}						\
		unlikely(__ret_warn_on);			\
	})
#endif

#endif /* EFX_KERNEL_COMPAT_H */
