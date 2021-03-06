/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2009 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#define EFX_IN_KCOMPAT_C 1

#include "efx.h"
#include <linux/mii.h>
#include <linux/ethtool.h>
#include <linux/random.h>
#include <linux/pci.h>
#include <linux/spinlock.h>
#include <linux/rtnetlink.h>
#include <linux/bootmem.h>
#include <asm/uaccess.h>

/*
 * Kernel backwards compatibility
 *
 * This file provides functionality missing from earlier kernels.
 */

/**************************************************************************
 *
 * unregister_netdevice_notifier : Has a race before 2.6.17
 *
 **************************************************************************
 *
 */

#ifdef EFX_NEED_UNREGISTER_NETDEVICE_NOTIFIER_FIX
/**
 * efx_unregister_netdevice_notifier - fixed unregister_netdevice_notifier
 * @nb:		notifier to unregister
 *
 * unregister_netdevice_notifier() does not wait for the notifier
 * to be unused before 2.6.17.  This wrapper fixes that.
 */
int efx_unregister_netdevice_notifier(struct notifier_block *nb)
{
	int res;

	res = unregister_netdevice_notifier(nb);
	/* Ensure any outstanding calls complete. */
	rtnl_lock();
	rtnl_unlock();
	return res;
}
#endif /* NEED_EFX_UNREGISTER_NETDEVICE_NOTIFIER */

#ifdef EFX_NEED_COMPOUND_PAGE_FIX

void efx_compound_page_destructor(struct page *page)
{
	/* Fake up page state to keep __free_pages happy */
	set_page_count(page, 1);
	page[1].mapping = NULL;

	__free_pages(page, (unsigned long)page[1].index);
}

#endif /* NEED_COMPOUND_PAGE_FIX */

/**************************************************************************
 *
 * print_hex_dump, taken from lib/hexdump.c.
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_HEX_DUMP

#define hex_asc(x)	"0123456789abcdef"[x]
#define isascii(c) (((unsigned char)(c))<=0x7f)

static void hex_dump_to_buffer(const void *buf, size_t len, int rowsize,
			       int groupsize, char *linebuf, size_t linebuflen,
			       int ascii)
{
        const u8 *ptr = buf;
        u8 ch;
        int j, lx = 0;
        int ascii_column;

        if (rowsize != 16 && rowsize != 32)
                rowsize = 16;

        if (!len)
                goto nil;
        if (len > rowsize)              /* limit to one line at a time */
                len = rowsize;
        if ((len % groupsize) != 0)     /* no mixed size output */
                groupsize = 1;

        switch (groupsize) {
        case 8: {
                const u64 *ptr8 = buf;
                int ngroups = len / groupsize;

                for (j = 0; j < ngroups; j++)
                        lx += scnprintf(linebuf + lx, linebuflen - lx,
				"%16.16llx ", (unsigned long long)*(ptr8 + j));
                ascii_column = 17 * ngroups + 2;
                break;
        }

        case 4: {
                const u32 *ptr4 = buf;
                int ngroups = len / groupsize;

                for (j = 0; j < ngroups; j++)
                        lx += scnprintf(linebuf + lx, linebuflen - lx,
				"%8.8x ", *(ptr4 + j));
                ascii_column = 9 * ngroups + 2;
                break;
        }

        case 2: {
                const u16 *ptr2 = buf;
                int ngroups = len / groupsize;

                for (j = 0; j < ngroups; j++)
                        lx += scnprintf(linebuf + lx, linebuflen - lx,
				"%4.4x ", *(ptr2 + j));
                ascii_column = 5 * ngroups + 2;
                break;
        }

        default:
                for (j = 0; (j < rowsize) && (j < len) && (lx + 4) < linebuflen;
                     j++) {
                        ch = ptr[j];
                        linebuf[lx++] = hex_asc(ch >> 4);
                        linebuf[lx++] = hex_asc(ch & 0x0f);
                        linebuf[lx++] = ' ';
                }
                ascii_column = 3 * rowsize + 2;
                break;
        }
        if (!ascii)
                goto nil;

        while (lx < (linebuflen - 1) && lx < (ascii_column - 1))
                linebuf[lx++] = ' ';
	/* Removed is_print() check */
        for (j = 0; (j < rowsize) && (j < len) && (lx + 2) < linebuflen; j++)
                linebuf[lx++] = isascii(ptr[j]) ? ptr[j] : '.';
nil:
        linebuf[lx++] = '\0';
}

void print_hex_dump(const char *level, const char *prefix_str, int prefix_type,
		    int rowsize, int groupsize,
		    const void *buf, size_t len, int ascii)
{
        const u8 *ptr = buf;
        int i, linelen, remaining = len;
        char linebuf[200];

        if (rowsize != 16 && rowsize != 32)
                rowsize = 16;

        for (i = 0; i < len; i += rowsize) {
                linelen = min(remaining, rowsize);
                remaining -= rowsize;
                hex_dump_to_buffer(ptr + i, linelen, rowsize, groupsize,
				   linebuf, sizeof(linebuf), ascii);

                switch (prefix_type) {
                case DUMP_PREFIX_ADDRESS:
                        printk("%s%s%*p: %s\n", level, prefix_str,
			       (int)(2 * sizeof(void *)), ptr + i, linebuf);
                        break;
                case DUMP_PREFIX_OFFSET:
                        printk("%s%s%.8x: %s\n", level, prefix_str, i, linebuf);
                        break;
                default:
                        printk("%s%s%s\n", level, prefix_str, linebuf);
                        break;
                }
        }
}

#endif /* EFX_NEED_HEX_DUMP */

/**************************************************************************
 *
 * print_mac, from net/ethernet/eth.c in v2.6.24
 *
 **************************************************************************
 *
 */
#ifdef EFX_NEED_PRINT_MAC
char *print_mac(char *buf, const u8 *addr)
{
        sprintf(buf, "%02x:%02x:%02x:%02x:%02x:%02x",
                addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
        return buf;
}
#endif /* EFX_NEED_PRINT_MAC */

#ifdef EFX_NEED_CSUM_TCPUDP_NOFOLD
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,20)
__wsum
csum_tcpudp_nofold (__be32 saddr, __be32 daddr, unsigned short len,
		    unsigned short proto, __wsum sum)
#else
__wsum
csum_tcpudp_nofold (unsigned long saddr, unsigned long daddr,
		    unsigned short len, unsigned short proto, __wsum sum)
#endif
{
	unsigned long result;

	result = (__force u64)saddr + (__force u64)daddr +
		(__force u64)sum + ((len + proto) << 8);

	/* Fold down to 32-bits so we don't lose in the typedef-less network stack.  */
	/* 64 to 33 */
	result = (result & 0xffffffff) + (result >> 32);
	/* 33 to 32 */
	result = (result & 0xffffffff) + (result >> 32);
	return (__force __wsum)result;

}
#endif /* EFX_NEED_CSUM_TCPUDP_NOFOLD */

#ifdef EFX_NEED_RANDOM_ETHER_ADDR
/* Generate random MAC address */
void efx_random_ether_addr(uint8_t *addr) {
        get_random_bytes (addr, ETH_ALEN);
	addr [0] &= 0xfe;       /* clear multicast bit */
	addr [0] |= 0x02;       /* set local assignment bit (IEEE802) */
}
#endif /* EFX_NEED_RANDOM_ETHER_ADDR */

#ifdef EFX_NEED_MSECS_TO_JIFFIES
/*
 * When we convert to jiffies then we interpret incoming values
 * the following way:
 *
 * - negative values mean 'infinite timeout' (MAX_JIFFY_OFFSET)
 *
 * - 'too large' values [that would result in larger than
 *   MAX_JIFFY_OFFSET values] mean 'infinite timeout' too.
 *
 * - all other values are converted to jiffies by either multiplying
 *   the input value by a factor or dividing it with a factor
 *
 * We must also be careful about 32-bit overflows.
 */
#ifndef MSEC_PER_SEC
#define MSEC_PER_SEC	1000L
#endif
unsigned long msecs_to_jiffies(const unsigned int m)
{
	/*
	 * Negative value, means infinite timeout:
	 */
	if ((int)m < 0)
		return MAX_JIFFY_OFFSET;

#if HZ <= MSEC_PER_SEC && !(MSEC_PER_SEC % HZ)
	/*
	 * HZ is equal to or smaller than 1000, and 1000 is a nice
	 * round multiple of HZ, divide with the factor between them,
	 * but round upwards:
	 */
	return (m + (MSEC_PER_SEC / HZ) - 1) / (MSEC_PER_SEC / HZ);
#elif HZ > MSEC_PER_SEC && !(HZ % MSEC_PER_SEC)
	/*
	 * HZ is larger than 1000, and HZ is a nice round multiple of
	 * 1000 - simply multiply with the factor between them.
	 *
	 * But first make sure the multiplication result cannot
	 * overflow:
	 */
	if (m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return m * (HZ / MSEC_PER_SEC);
#else
	/*
	 * Generic case - multiply, round and divide. But first
	 * check that if we are doing a net multiplication, that
	 * we wouldnt overflow:
	 */
	if (HZ > MSEC_PER_SEC && m > jiffies_to_msecs(MAX_JIFFY_OFFSET))
		return MAX_JIFFY_OFFSET;

	return (m * HZ + MSEC_PER_SEC - 1) / MSEC_PER_SEC;
#endif
}
#endif /* EFX_NEED_MSECS_TO_JIFFIES */

#ifdef EFX_NEED_MSLEEP
/**
 * msleep - sleep safely even with waitqueue interruptions
 * @msecs: Time in milliseconds to sleep for
 */
void msleep(unsigned int msecs)
{
	unsigned long timeout = msecs_to_jiffies(msecs) + 1;

	while (timeout)
		timeout = schedule_timeout_uninterruptible(timeout);
}
#endif

#ifdef EFX_USE_I2C_LEGACY

struct i2c_client *i2c_new_device(struct i2c_adapter *adap,
				  struct i2c_board_info *info)
{
	return i2c_new_probed_device(adap, info, NULL);
}

struct i2c_client *i2c_new_probed_device(struct i2c_adapter *adap,
					 struct i2c_board_info *info,
					 const unsigned short *addr_list)
{
	int (*probe)(struct i2c_client *, const struct i2c_device_id *);
	struct i2c_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->adapter = adap;
	client->dev.platform_data = info->platform_data;
	client->flags = info->flags;
	client->addr = addr_list ? addr_list[0] : info->addr; /* FIXME */
	strlcpy(client->name, info->type, sizeof client->name);

	if (!strcmp(client->name, "sfc_lm87")) {
		client->driver = &efx_lm87_driver;
		probe = efx_lm87_probe;
	} else if (!strcmp(client->name, "max6646") ||
		   !strcmp(client->name, "max6647")) {
		client->driver = &efx_lm90_driver;
		probe = efx_lm90_probe;
	} else {
		BUG();
		probe = NULL;
	}

	if (i2c_attach_client(client))
		goto fail_client;

	if (probe(client, NULL))
		goto fail_attached;

	return client;

fail_attached:
	i2c_detach_client(client);
fail_client:
	kfree(client);
	return NULL;
}

void i2c_unregister_device(struct i2c_client *client)
{
	if (client->driver->detach_client) {
		client->driver->detach_client(client);
	} else {
		if (!i2c_detach_client(client))
			kfree(client);
	}
}

#endif /* EFX_USE_I2C_LEGACY */

#ifdef EFX_NEED_I2C_NEW_DUMMY

struct i2c_driver efx_i2c_dummy_driver = {
#ifdef EFX_USE_I2C_DRIVER_NAME
	.name = "sfc_i2c_dummy"
#else
	.driver.name = "sfc_i2c_dummy"
#endif
};

struct i2c_client *efx_i2c_new_dummy(struct i2c_adapter *adap, u16 address)
{
	struct i2c_client *client;

	client = kzalloc(sizeof(*client), GFP_KERNEL);
	if (!client)
		return NULL;

	client->adapter = adap;
	client->addr = address;
	strcpy(client->name, efx_i2c_dummy_driver.driver.name);

	client->driver = &efx_i2c_dummy_driver;

	if (i2c_attach_client(client)) {
		kfree(client);
		return NULL;
	}

	return client;
}

#endif /* EFX_NEED_I2C_NEW_DUMMY */

#ifdef EFX_NEED_PCI_CLEAR_MASTER

void pci_clear_master(struct pci_dev *dev)
{
	u16 old_cmd, cmd;

	pci_read_config_word(dev, PCI_COMMAND, &old_cmd);
	cmd = old_cmd & ~PCI_COMMAND_MASTER;
	if (cmd != old_cmd) {
		dev_dbg(&dev->dev, "disabling bus mastering\n");
		pci_write_config_word(dev, PCI_COMMAND, cmd);
	}
	dev->is_busmaster = false;
}

#endif /* EFX_NEED_PCI_CLEAR_MASTER */


#ifdef EFX_NEED_PCI_WAKE_FROM_D3

#ifndef PCI_D3hot
#define PCI_D3hot 3
#endif

int pci_wake_from_d3(struct pci_dev *dev, bool enable)
{
	/* We always support waking from D3hot on boards that do WoL,
	 * so no need to check capabilities */
	return pci_enable_wake(dev, PCI_D3hot, enable);
}

#endif /* EFX_NEED_PCI_WAKE_FROM_D3 */

#ifdef EFX_NEED_UNMASK_MSIX_VECTORS

#ifdef EFX_HAVE_MSIX_TABLE_RESERVED

void efx_unmask_msix_vectors(struct pci_dev *pci_dev)
{
	dev_dbg(&pci_dev->dev, "cannot unmask MSI-X interrupt\n");
}

#else

#include <linux/pci_regs.h>

#define PCI_MSIX_TABLE         4
#define PCI_MSIX_PBA           8
#define  PCI_MSIX_BIR          0x7

void efx_unmask_msix_vectors(struct pci_dev *pci_dev)
{
	struct efx_nic *efx = pci_get_drvdata(pci_dev);
	resource_size_t membase_phys;
	void __iomem *membase;
	int msix, offset, bar, length, i;
	u32 dword, mask;

	if (efx->interrupt_mode != EFX_INT_MODE_MSIX)
		return;

	/* Find the location (bar, offset) of the MSI-X table */
	msix = pci_find_capability(pci_dev, PCI_CAP_ID_MSIX);
	if (!msix)
		return;
	pci_read_config_dword(pci_dev, msix + PCI_MSIX_TABLE, &dword);
	bar = dword & PCI_MSIX_BIR;
	offset = dword & ~PCI_MSIX_BIR;

	/* Map enough of the table for all our interrupts */
	membase_phys = pci_resource_start(pci_dev, bar);
	length = efx->n_channels * 0x10;
	membase = ioremap_nocache(membase_phys + offset, length);
	if (!membase) {
		dev_dbg(&pci_dev->dev, "failed to remap MSI-X table\n");
		return;
	}

	/* Unmask every vector */
	for (i = 0; i < efx->n_channels; i++) {
		offset = (i << 4) + 0xc;
		mask = readl(membase + offset);
		writel(mask & ~0x1, membase + offset);
		dev_dbg(&pci_dev->dev, "writing value %d for channel %d\n",
			mask & ~0x1, i);
	}

	/* Release the mapping */
	iounmap(membase);
}

#endif /* EFX_HAVE_MSIX_TABLE_RESERVED */

#endif /* EFX_NEED_UNMASK_MSIX_VECTORS */
