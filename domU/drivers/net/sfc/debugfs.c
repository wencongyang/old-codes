/****************************************************************************
 * Driver for Solarflare Solarstorm network controllers and boards
 * Copyright 2005-2006 Fen Systems Ltd.
 * Copyright 2006-2009 Solarflare Communications Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published
 * by the Free Software Foundation, incorporated herein by reference.
 */

#include <linux/module.h>
#include <linux/pci.h>
/* For out-of-tree builds we always need procfs, if only for a compatibility
 * symlink.
 */
#include <linux/proc_fs.h>
#include <linux/dcache.h>
#include <linux/seq_file.h>
#include "net_driver.h"
#include "efx.h"
#include "debugfs.h"
#include "nic.h"

/* EFX_USE_DEBUGFS is defined by kernel_compat.h so we can't decide whether to
 * include this earlier.
 */
#ifdef EFX_USE_DEBUGFS
#include <linux/debugfs.h>
#endif

#ifndef EFX_USE_DEBUGFS

static void efx_debugfs_remove(struct proc_dir_entry *entry)
{
	if (entry)
		remove_proc_entry(entry->name, entry->parent);
}
#define debugfs_remove efx_debugfs_remove

#define debugfs_create_dir proc_mkdir
#define debugfs_create_symlink proc_symlink

#endif /* !EFX_USE_DEBUGFS */

/* Parameter definition bound to a structure - each file has one of these */
struct efx_debugfs_bound_param {
	const struct efx_debugfs_parameter *param;
	void *structure;
};


/* Maximum length for a name component or symlink target */
#define EFX_DEBUGFS_NAME_LEN 32


/* Top-level debug directory ([/sys/kernel]/debug/sfc) */
static efx_debugfs_entry *efx_debug_root;

/* "cards" directory ([/sys/kernel]/debug/sfc/cards) */
static efx_debugfs_entry *efx_debug_cards;


/* Sequential file interface to bound parameters */

#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEBUGFS)

static int efx_debugfs_seq_show(struct seq_file *file, void *v)
{
	struct efx_debugfs_bound_param *binding = file->private;

	return binding->param->reader(file,
				      binding->structure +
				      binding->param->offset);
}

static int efx_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, efx_debugfs_seq_show, inode->i_private);
}

#else /* EFX_USE_KCOMPAT && !EFX_USE_DEBUGFS */

static int efx_debugfs_seq_show(struct seq_file *file, void *v)
{
	struct proc_dir_entry *entry = file->private;
	struct efx_debugfs_parameter *param = entry->data;
	void *structure = (void *)entry->read_proc;

	if (!structure)
		return -EIO;

	return param->reader(file, structure + param->offset);
}

static int efx_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, efx_debugfs_seq_show, PROC_I(inode)->pde);
}

#endif /* !EFX_USE_KCOMPAT || EFX_USE_DEBUGFS */


static struct file_operations efx_debugfs_file_ops = {
	.owner   = THIS_MODULE,
	.open    = efx_debugfs_open,
	.read    = seq_read,
	.llseek  = seq_lseek,
	.release = seq_release
};


#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEBUGFS)

/**
 * efx_fini_debugfs_child - remove a named child of a debugfs directory
 * @dir:		Directory
 * @name:		Name of child
 *
 * This removes the named child from the directory, if it exists.
 */
void efx_fini_debugfs_child(efx_debugfs_entry *dir, const char *name)
{
	struct qstr child_name;
	efx_debugfs_entry *child;

	child_name.len = strlen(name);
	child_name.name = name;
	child_name.hash = full_name_hash(child_name.name, child_name.len);
	child = d_lookup(dir, &child_name);
	if (child) {
		/* If it's a "regular" file, free its parameter binding */
		if (S_ISREG(child->d_inode->i_mode))
			kfree(child->d_inode->i_private);
		debugfs_remove(child);
		dput(child);
	}
}

#else /* EFX_USE_KCOMPAT && !EFX_USE_DEBUGFS */

void efx_fini_debugfs_child(struct proc_dir_entry *dir, const char *name)
{
	remove_proc_entry(name, dir);
}

#endif /* !EFX_USE_KCOMPAT || EFX_USE_DEBUGFS */

/*
 * Remove a debugfs directory.
 *
 * This removes the named parameter-files and sym-links from the
 * directory, and the directory itself.  It does not do any recursion
 * to subdirectories.
 */
static void efx_fini_debugfs_dir(efx_debugfs_entry *dir,
				 struct efx_debugfs_parameter *params,
				 const char *const *symlink_names)
{
	if (!dir)
		return;

	while (params->name) {
		efx_fini_debugfs_child(dir, params->name);
		params++;
	}
	while (symlink_names && *symlink_names) {
		efx_fini_debugfs_child(dir, *symlink_names);
		symlink_names++;
	}
	debugfs_remove(dir);
}

/* Functions for printing various types of parameter. */

int efx_debugfs_read_uint(struct seq_file *file, void *data)
{
	return seq_printf(file, "%#x\n", *(unsigned int *)data);
}

int efx_debugfs_read_int(struct seq_file *file, void *data)
{
	return seq_printf(file, "%d\n", *(int *)data);
}

int efx_debugfs_read_atomic(struct seq_file *file, void *data)
{
	unsigned int value = atomic_read((atomic_t *) data);

	return seq_printf(file, "%#x\n", value);
}

int efx_debugfs_read_dword(struct seq_file *file, void *data)
{
	unsigned int value = EFX_DWORD_FIELD(*(efx_dword_t *) data,
					     EFX_DWORD_0);

	return seq_printf(file, "%#x\n", value);
}

int efx_debugfs_read_bool(struct seq_file *file, void *data)
{
	return seq_printf(file, "%d\n", *(bool *)data);
}

static int efx_debugfs_read_int_mode(struct seq_file *file, void *data)
{
	unsigned int value = *(enum efx_int_mode *) data;

	return seq_printf(file, "%d => %s\n", value,
			  STRING_TABLE_LOOKUP(value, efx_interrupt_mode));
}

#define EFX_INT_MODE_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,			\
		      enum efx_int_mode, efx_debugfs_read_int_mode)

static int efx_debugfs_read_loop_mode(struct seq_file *file, void *data)
{
	unsigned int value = *(enum efx_loopback_mode *)data;

	return seq_printf(file, "%d => %s\n", value,
			  STRING_TABLE_LOOKUP(value, efx_loopback_mode));
}

#define EFX_LOOPBACK_MODE_PARAMETER(container_type, parameter)		\
	EFX_PARAMETER(container_type, parameter,			\
		      enum efx_loopback_mode, efx_debugfs_read_loop_mode)

int efx_debugfs_read_string(struct seq_file *file, void *data)
{
	return seq_puts(file, (const char *)data);
}


/**
 * efx_init_debugfs_files - create parameter-files in a debugfs directory
 * @parent:		Containing directory
 * @params:		Pointer to zero-terminated parameter definition array
 * @structure:		Structure containing parameters
 *
 * Add parameter-files to the given debugfs directory.  Return a
 * negative error code or 0 on success.
 */
static int efx_init_debugfs_files(efx_debugfs_entry *parent,
				  struct efx_debugfs_parameter *params,
				  void *structure)
{
	struct efx_debugfs_parameter *param = params;

	while (param->name) {
		efx_debugfs_entry *entry;
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEBUGFS)
		struct efx_debugfs_bound_param *binding;

		binding = kmalloc(sizeof(*binding), GFP_KERNEL);
		if (!binding)
			goto err;
		binding->param = param;
		binding->structure = structure;

		entry = debugfs_create_file(param->name, S_IRUGO, parent,
					    binding, &efx_debugfs_file_ops);
		if (!entry) {
			kfree(binding);
			goto err;
		}
#else
		entry = create_proc_entry(param->name, S_IRUGO, parent);
		if (!entry)
			goto err;
		/*
		 * We have no good way to free a binding created here.
		 * However, once we install our file_operations the
		 * read_proc pointer becomes redundant and we can
		 * abuse it as a structure pointer.
		 */
		entry->data = param;
		entry->read_proc = NULL;
		smp_wmb();
		entry->proc_fops = &efx_debugfs_file_ops;
		smp_wmb();
		entry->read_proc = (read_proc_t *) structure;
#endif

		param++;
	}

	return 0;

 err:
	while (param != params) {
		param--;
		efx_fini_debugfs_child(parent, param->name);
	}
	return -ENOMEM;
}

/**
 * efx_init_debugfs_netdev - create debugfs sym-links for net device
 * @net_dev:		Net device
 *
 * Create sym-links named after @net_dev to the debugfs directories for
 * the corresponding NIC and  port.  Return a negative error code or 0 on
 * success.  The sym-links must be cleaned up using
 * efx_fini_debugfs_netdev().
 */
int efx_init_debugfs_netdev(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);
	char name[EFX_DEBUGFS_NAME_LEN];
	char target[EFX_DEBUGFS_NAME_LEN];
	size_t len;

	if (snprintf(name, sizeof(name), "nic_%s", net_dev->name) >=
	    sizeof(name))
		return -ENAMETOOLONG;
	if (snprintf(target, sizeof(target), "cards/%s", pci_name(efx->pci_dev))
	    >= sizeof(target))
		return -ENAMETOOLONG;
	efx->debug_symlink = debugfs_create_symlink(name,
						    efx_debug_root, target);
	if (!efx->debug_symlink)
		return -ENOMEM;

	if (snprintf(name, sizeof(name), "if_%s", net_dev->name) >=
	    sizeof(name))
		return -ENAMETOOLONG;
	len = snprintf(target, sizeof(target),
		       "cards/%s/port0", pci_name(efx->pci_dev));
	if (len >= sizeof(target))
		return -ENAMETOOLONG;
	efx->debug_port_symlink = debugfs_create_symlink(name,
							 efx_debug_root,
							 target);
	if (!efx->debug_port_symlink)
		return -ENOMEM;

	return 0;
}

/**
 * efx_fini_debugfs_netdev - remove debugfs sym-links for net device
 * @net_dev:		Net device
 *
 * Remove sym-links created for @net_dev by efx_init_debugfs_netdev().
 */
void efx_fini_debugfs_netdev(struct net_device *net_dev)
{
	struct efx_nic *efx = netdev_priv(net_dev);

	debugfs_remove(efx->debug_port_symlink);
	efx->debug_port_symlink = NULL;
	debugfs_remove(efx->debug_symlink);
	efx->debug_symlink = NULL;
}

/* Per-port parameters */
static struct efx_debugfs_parameter efx_debugfs_port_parameters[] = {
	EFX_NAMED_PARAMETER(enabled, struct efx_nic, port_enabled,
			    bool, efx_debugfs_read_bool),
#if defined(EFX_USE_KCOMPAT) && !defined(NETIF_F_LRO)
	EFX_BOOL_PARAMETER(struct efx_nic, lro_enabled),
#endif
	EFX_BOOL_PARAMETER(struct efx_nic, rx_checksum_enabled),
	EFX_ATOMIC_PARAMETER(struct efx_nic, netif_stop_count),
	EFX_NAMED_PARAMETER(link_up, struct efx_nic, link_state.up,
			    bool, efx_debugfs_read_bool),
	EFX_BOOL_PARAMETER(struct efx_nic, xmac_poll_required),
	EFX_NAMED_PARAMETER(link_fd, struct efx_nic, link_state.fd,
			    bool, efx_debugfs_read_bool),
	EFX_NAMED_PARAMETER(link_speed, struct efx_nic, link_state.speed,
			    unsigned int, efx_debugfs_read_uint),
	EFX_BOOL_PARAMETER(struct efx_nic, promiscuous),
	EFX_U64_PARAMETER(struct efx_nic, loopback_modes),
	EFX_LOOPBACK_MODE_PARAMETER(struct efx_nic, loopback_mode),
	EFX_UINT_PARAMETER(struct efx_nic, phy_type),
	EFX_STRING_PARAMETER(struct efx_nic, phy_name),
	EFX_NAMED_PARAMETER(phy_id, struct efx_nic, mdio.prtad,
			    int, efx_debugfs_read_int),
	EFX_UINT_PARAMETER(struct efx_nic, n_link_state_changes),
	{NULL},
};

/**
 * efx_init_debugfs_port - create debugfs directory for port
 * @efx:		Efx NIC
 *
 * Create a debugfs directory containing parameter-files for @efx.
 * Return a negative error code or 0 on success.  The directory must be
 * cleaned up using efx_fini_debugfs_port().
 */
int efx_init_debugfs_port(struct efx_nic *efx)
{
	int rc;

	/* Create directory */
	efx->debug_port_dir = debugfs_create_dir("port0", efx->debug_dir);
	if (!efx->debug_port_dir)
		return -ENOMEM;

	/* Create files */
	rc = efx_init_debugfs_files(efx->debug_port_dir,
				    efx_debugfs_port_parameters,
				    efx);
	if (rc)
		efx_fini_debugfs_port(efx);

	return rc;
}

/**
 * efx_fini_debugfs_port - remove debugfs directory for port
 * @efx:		Efx NIC
 *
 * Remove directory created for @efx by efx_init_debugfs_port().
 */
void efx_fini_debugfs_port(struct efx_nic *efx)
{
	efx_fini_debugfs_dir(efx->debug_port_dir,
			     efx_debugfs_port_parameters, NULL);
	efx->debug_port_dir = NULL;
}

/**
 * efx_extend_debugfs_port - add parameter-files to directory for port
 * @efx:		Efx NIC
 * @structure:		Structure containing parameters
 * @params:		Pointer to zero-terminated parameter definition array
 *
 * Add parameter-files to the debugfs directory for @efx.  Return
 * a negative error code or 0 on success.  This is intended for
 * PHY-specific parameters.  The files must be cleaned up using
 * efx_trim_debugfs_port().
 */
int efx_extend_debugfs_port(struct efx_nic *efx,
			    void *structure,
			    struct efx_debugfs_parameter *params)
{
	return efx_init_debugfs_files(efx->debug_port_dir, params, structure);
}

/**
 * efx_trim_debugfs_port - remove parameter-files from directory for port
 * @efx:		Efx NIC
 * @params:		Pointer to zero-terminated parameter definition array
 *
 * Remove parameter-files previously added to the debugfs directory
 * for @efx using efx_extend_debugfs_port().
 */
void efx_trim_debugfs_port(struct efx_nic *efx,
			   struct efx_debugfs_parameter *params)
{
	efx_debugfs_entry *dir = efx->debug_port_dir;

	if (dir) {
		struct efx_debugfs_parameter *field;
		for (field = params; field->name; field++)
			efx_fini_debugfs_child(dir, field->name);
	}
}

/* Per-TX-queue parameters */
static struct efx_debugfs_parameter efx_debugfs_tx_queue_parameters[] = {
	EFX_UINT_PARAMETER(struct efx_tx_queue, insert_count),
	EFX_UINT_PARAMETER(struct efx_tx_queue, write_count),
	EFX_UINT_PARAMETER(struct efx_tx_queue, read_count),
	EFX_INT_PARAMETER(struct efx_tx_queue, stopped),
	EFX_UINT_PARAMETER(struct efx_tx_queue, tso_bursts),
	EFX_UINT_PARAMETER(struct efx_tx_queue, tso_long_headers),
	EFX_UINT_PARAMETER(struct efx_tx_queue, tso_packets),
	{NULL},
};

static void efx_fini_debugfs_tx_queue(struct efx_tx_queue *tx_queue);

/**
 * efx_init_debugfs_tx_queue - create debugfs directory for TX queue
 * @tx_queue:		Efx TX queue
 *
 * Create a debugfs directory containing parameter-files for @tx_queue.
 * Return a negative error code or 0 on success.  The directory must be
 * cleaned up using efx_fini_debugfs_tx_queue().
 */
static int efx_init_debugfs_tx_queue(struct efx_tx_queue *tx_queue)
{
	char name[EFX_DEBUGFS_NAME_LEN];
	char target[EFX_DEBUGFS_NAME_LEN];
	int rc;

	/* Create directory */
	if (snprintf(name, sizeof(name), EFX_TX_QUEUE_NAME(tx_queue))
	    >= sizeof(name))
		goto err_len;
	tx_queue->debug_dir = debugfs_create_dir(name,
						 tx_queue->efx->debug_dir);
	if (!tx_queue->debug_dir)
		goto err_mem;

	/* Create files */
	rc = efx_init_debugfs_files(tx_queue->debug_dir,
				    efx_debugfs_tx_queue_parameters,
				    tx_queue);
	if (rc)
		goto err;

	/* Create symlink to channel */
	if (snprintf(target, sizeof(target),
		     "../" EFX_CHANNEL_NAME(tx_queue->channel)) >=
	    sizeof(target))
		goto err_len;
	if (!debugfs_create_symlink("channel", tx_queue->debug_dir, target))
		goto err_mem;

	/* Create symlink to port */
	if (!debugfs_create_symlink("port", tx_queue->debug_dir, "../port0"))
		goto err_mem;

	return 0;

 err_len:
	rc = -ENAMETOOLONG;
	goto err;
 err_mem:
	rc = -ENOMEM;
 err:
	efx_fini_debugfs_tx_queue(tx_queue);
	return rc;
}

/**
 * efx_fini_debugfs_tx_queue - remove debugfs directory for TX queue
 * @tx_queue:		Efx TX queue
 *
 * Remove directory created for @tx_queue by efx_init_debugfs_tx_queue().
 */
static void efx_fini_debugfs_tx_queue(struct efx_tx_queue *tx_queue)
{
	static const char *const symlink_names[] = {
		"channel", "port", NULL
	};

	efx_fini_debugfs_dir(tx_queue->debug_dir,
			     efx_debugfs_tx_queue_parameters, symlink_names);
	tx_queue->debug_dir = NULL;
}

/* Per-RX-queue parameters */
static struct efx_debugfs_parameter efx_debugfs_rx_queue_parameters[] = {
	EFX_INT_PARAMETER(struct efx_rx_queue, added_count),
	EFX_INT_PARAMETER(struct efx_rx_queue, removed_count),
	EFX_UINT_PARAMETER(struct efx_rx_queue, max_fill),
	EFX_UINT_PARAMETER(struct efx_rx_queue, fast_fill_trigger),
	EFX_UINT_PARAMETER(struct efx_rx_queue, fast_fill_limit),
	EFX_UINT_PARAMETER(struct efx_rx_queue, min_fill),
	EFX_UINT_PARAMETER(struct efx_rx_queue, min_overfill),
	EFX_UINT_PARAMETER(struct efx_rx_queue, alloc_page_count),
	EFX_UINT_PARAMETER(struct efx_rx_queue, alloc_skb_count),
	EFX_UINT_PARAMETER(struct efx_rx_queue, slow_fill_count),
	{NULL},
};

static void efx_fini_debugfs_rx_queue(struct efx_rx_queue *rx_queue);

/**
 * efx_init_debugfs_rx_queue - create debugfs directory for RX queue
 * @rx_queue:		Efx RX queue
 *
 * Create a debugfs directory containing parameter-files for @rx_queue.
 * Return a negative error code or 0 on success.  The directory must be
 * cleaned up using efx_fini_debugfs_rx_queue().
 */
static int efx_init_debugfs_rx_queue(struct efx_rx_queue *rx_queue)
{
	char name[EFX_DEBUGFS_NAME_LEN];
	char target[EFX_DEBUGFS_NAME_LEN];
	int rc;

	/* Create directory */
	if (snprintf(name, sizeof(name), EFX_RX_QUEUE_NAME(rx_queue))
	    >= sizeof(name))
		goto err_len;
	rx_queue->debug_dir = debugfs_create_dir(name,
						 rx_queue->efx->debug_dir);
	if (!rx_queue->debug_dir)
		goto err_mem;

	/* Create files */
	rc = efx_init_debugfs_files(rx_queue->debug_dir,
				    efx_debugfs_rx_queue_parameters,
				    rx_queue);
	if (rc)
		goto err;

	/* Create symlink to channel */
	if (snprintf(target, sizeof(target),
		     "../" EFX_CHANNEL_NAME(rx_queue->channel)) >=
	    sizeof(target))
		goto err_len;
	if (!debugfs_create_symlink("channel", rx_queue->debug_dir, target))
		goto err_mem;

	return 0;

 err_len:
	rc = -ENAMETOOLONG;
	goto err;
 err_mem:
	rc = -ENOMEM;
 err:
	efx_fini_debugfs_rx_queue(rx_queue);
	return rc;
}

/**
 * efx_fini_debugfs_rx_queue - remove debugfs directory for RX queue
 * @rx_queue:		Efx RX queue
 *
 * Remove directory created for @rx_queue by efx_init_debugfs_rx_queue().
 */
static void efx_fini_debugfs_rx_queue(struct efx_rx_queue *rx_queue)
{
	const char *const symlink_names[] = {
		"channel", NULL
	};

	efx_fini_debugfs_dir(rx_queue->debug_dir,
			     efx_debugfs_rx_queue_parameters, symlink_names);
	rx_queue->debug_dir = NULL;
}

/* Per-channel parameters */
static struct efx_debugfs_parameter efx_debugfs_channel_parameters[] = {
	EFX_BOOL_PARAMETER(struct efx_channel, enabled),
	EFX_INT_PARAMETER(struct efx_channel, irq),
	EFX_UINT_PARAMETER(struct efx_channel, irq_moderation),
	EFX_UINT_PARAMETER(struct efx_channel, eventq_read_ptr),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_tobe_disc),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_ip_frag),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_ip_hdr_chksum_err),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_tcp_udp_chksum_err),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_eth_crc_err),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_mcast_mismatch),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_frm_trunc),
	EFX_UINT_PARAMETER(struct efx_channel, n_rx_overlength),
	EFX_UINT_PARAMETER(struct efx_channel, n_skbuff_leaks),
	EFX_INT_PARAMETER(struct efx_channel, rx_alloc_level),
	EFX_INT_PARAMETER(struct efx_channel, rx_alloc_push_pages),
	{NULL},
};

static void efx_fini_debugfs_channel(struct efx_channel *channel);

/**
 * efx_init_debugfs_channel - create debugfs directory for channel
 * @channel:		Efx channel
 *
 * Create a debugfs directory containing parameter-files for @channel.
 * Return a negative error code or 0 on success.  The directory must be
 * cleaned up using efx_fini_debugfs_channel().
 */
static int efx_init_debugfs_channel(struct efx_channel *channel)
{
	char name[EFX_DEBUGFS_NAME_LEN];
	int rc;

	/* Create directory */
	if (snprintf(name, sizeof(name), EFX_CHANNEL_NAME(channel))
	    >= sizeof(name))
		goto err_len;
	channel->debug_dir = debugfs_create_dir(name, channel->efx->debug_dir);
	if (!channel->debug_dir)
		goto err_mem;

	/* Create files */
	rc = efx_init_debugfs_files(channel->debug_dir,
				    efx_debugfs_channel_parameters,
				    channel);
	if (rc)
		goto err;

	return 0;

 err_len:
	rc = -ENAMETOOLONG;
	goto err;
 err_mem:
	rc = -ENOMEM;
 err:
	efx_fini_debugfs_channel(channel);
	return rc;
}

/**
 * efx_fini_debugfs_channel - remove debugfs directory for channel
 * @channel:		Efx channel
 *
 * Remove directory created for @channel by efx_init_debugfs_channel().
 */
static void efx_fini_debugfs_channel(struct efx_channel *channel)
{
	efx_fini_debugfs_dir(channel->debug_dir,
			     efx_debugfs_channel_parameters, NULL);
	channel->debug_dir = NULL;
}

/* Per-NIC parameters */
static struct efx_debugfs_parameter efx_debugfs_nic_parameters[] = {
	EFX_INT_PARAMETER(struct efx_nic, legacy_irq),
	EFX_INT_PARAMETER(struct efx_nic, n_rx_queues),
	EFX_UINT_PARAMETER(struct efx_nic, rx_buffer_len),
	EFX_INT_MODE_PARAMETER(struct efx_nic, interrupt_mode),
	EFX_UINT_PARAMETER(struct efx_nic, state),
	{.name = "hardware_desc",
	 .offset = 0,
	 .reader = efx_nic_debugfs_read_desc},
	{NULL},
};

/* Per-NIC error counts */
static struct efx_debugfs_parameter efx_debugfs_nic_error_parameters[] = {
	EFX_ATOMIC_PARAMETER(struct efx_nic_errors, missing_event),
	EFX_ATOMIC_PARAMETER(struct efx_nic_errors, rx_reset),
	EFX_ATOMIC_PARAMETER(struct efx_nic_errors, rx_desc_fetch),
	EFX_ATOMIC_PARAMETER(struct efx_nic_errors, tx_desc_fetch),
	EFX_ATOMIC_PARAMETER(struct efx_nic_errors, spurious_tx),
	{NULL},
};

/**
 * efx_init_debugfs_channels - create debugfs directories for NIC channels
 * @efx:		Efx NIC
 *
 * Create subdirectories of @efx's debugfs directory for all the
 * channels, RX queues and TX queues used by this driver.  Return a
 * negative error code or 0 on success.  The subdirectories must be
 * cleaned up using efx_fini_debugfs_channels().
 */
int efx_init_debugfs_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_rx_queue *rx_queue;
	struct efx_tx_queue *tx_queue;
	int rc;

	efx_for_each_channel(channel, efx) {
		rc = efx_init_debugfs_channel(channel);
		if (rc)
			goto err;
	}

	efx_for_each_rx_queue(rx_queue, efx) {
		rc = efx_init_debugfs_rx_queue(rx_queue);
		if (rc)
			goto err;
	}

	efx_for_each_tx_queue(tx_queue, efx) {
		rc = efx_init_debugfs_tx_queue(tx_queue);
		if (rc)
			goto err;
	}

	return 0;

 err:
	efx_fini_debugfs_channels(efx);
	return rc;
}

/**
 * efx_fini_debugfs_channels - remove debugfs directories for NIC queues
 * @efx:		Efx NIC
 *
 * Remove subdirectories of @efx's debugfs directory created by
 * efx_init_debugfs_channels().
 */
void efx_fini_debugfs_channels(struct efx_nic *efx)
{
	struct efx_channel *channel;
	struct efx_rx_queue *rx_queue;
	struct efx_tx_queue *tx_queue;

	efx_for_each_tx_queue(tx_queue, efx)
		efx_fini_debugfs_tx_queue(tx_queue);

	efx_for_each_rx_queue(rx_queue, efx)
		efx_fini_debugfs_rx_queue(rx_queue);

	efx_for_each_channel(channel, efx)
		efx_fini_debugfs_channel(channel);
}

/**
 * efx_init_debugfs_nic - create debugfs directory for NIC
 * @efx:		Efx NIC
 *
 * Create debugfs directory containing parameter-files for @efx,
 * and a subdirectory "errors" containing per-NIC error counts.
 * Return a negative error code or 0 on success.  The directories
 * must be cleaned up using efx_fini_debugfs_nic().
 */
int efx_init_debugfs_nic(struct efx_nic *efx)
{
	int rc;

	/* Create directory */
	efx->debug_dir = debugfs_create_dir(pci_name(efx->pci_dev),
					    efx_debug_cards);
	if (!efx->debug_dir)
		goto err_mem;

	/* Create errors directory */
	efx->errors.debug_dir = debugfs_create_dir("errors", efx->debug_dir);
	if (!efx->errors.debug_dir)
		goto err_mem;

	/* Create files */
	rc = efx_init_debugfs_files(efx->debug_dir,
				    efx_debugfs_nic_parameters, efx);
	if (rc)
		goto err;
	rc = efx_init_debugfs_files(efx->errors.debug_dir,
				    efx_debugfs_nic_error_parameters,
				    &efx->errors);
	if (rc)
		goto err;

	return 0;

 err_mem:
	rc = -ENOMEM;
 err:
	efx_fini_debugfs_nic(efx);
	return rc;
}

/**
 * efx_fini_debugfs_nic - remove debugfs directories for NIC
 * @efx:		Efx NIC
 *
 * Remove debugfs directories created for @efx by efx_init_debugfs_nic().
 */
void efx_fini_debugfs_nic(struct efx_nic *efx)
{
	efx_fini_debugfs_dir(efx->errors.debug_dir,
			     efx_debugfs_nic_error_parameters, NULL);
	efx->errors.debug_dir = NULL;
	efx_fini_debugfs_dir(efx->debug_dir, efx_debugfs_nic_parameters, NULL);
	efx->debug_dir = NULL;
}

/**
 * efx_init_debugfs - create debugfs directories for sfc driver
 *
 * Create debugfs directories "sfc" and "sfc/cards".  This must be
 * called before any of the other functions that create debugfs
 * directories.  Return a negative error code or 0 on success.  The
 * directories must be cleaned up using efx_fini_debugfs().
 */
int efx_init_debugfs(void)
{
	/* Create top-level directory */
#if !defined(EFX_USE_KCOMPAT) || defined(EFX_USE_DEBUGFS)
	efx_debug_root = debugfs_create_dir("sfc", NULL);
#else
	efx_debug_root = proc_mkdir("driver/sfc", NULL);
#endif
	if (!efx_debug_root)
		goto err;

	/* Create "cards" directory */
	efx_debug_cards = debugfs_create_dir("cards", efx_debug_root);
	if (!efx_debug_cards)
		goto err;

#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_DEBUGFS)
	/* Create compatibility sym-link */
	if (!proc_symlink("driver/sfc", NULL, "/sys/kernel/debug/sfc"))
		goto err;
#endif
	return 0;

 err:
	efx_fini_debugfs();
	return -ENOMEM;
}

/**
 * efx_fini_debugfs - remove debugfs directories for sfc driver
 *
 * Remove directories created by efx_init_debugfs().
 */
void efx_fini_debugfs(void)
{
#if defined(EFX_USE_KCOMPAT) && defined(EFX_USE_DEBUGFS)
	remove_proc_entry("driver/sfc", NULL);
#endif
	debugfs_remove(efx_debug_cards);
	efx_debug_cards = NULL;
	debugfs_remove(efx_debug_root);
	efx_debug_root = NULL;
}
