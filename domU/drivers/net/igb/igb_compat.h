#ifndef __IGB_COMPAT_H__
#define __IGB_COMPAT_H__

#include <linux/if_vlan.h>
#include <linux/pci.h>

typedef unsigned int bool;

#define ETH_FCS_LEN               4

static inline struct net_device *vlan_group_get_device(struct vlan_group *vg,
						       int vlan_id)
{
	return vg->vlan_devices[vlan_id];
}

static inline void vlan_group_set_device(struct vlan_group *vg, int vlan_id,
					 struct net_device *dev)
{
	vg->vlan_devices[vlan_id] = NULL;
}

/* generic boolean compatibility */
#define true 1
#define false 0

#ifndef PCI_VDEVICE
#define PCI_VDEVICE(ven, dev)        \
        PCI_VENDOR_ID_##ven, (dev),  \
    PCI_ANY_ID, PCI_ANY_ID, 0, 0
#endif

static inline int pci_channel_offline(struct pci_dev *pdev)
{
    return (pdev->error_state != pci_channel_io_normal);
}

#ifndef round_jiffies
#define round_jiffies(x) x
#endif

#define tcp_hdr(skb) (skb->h.th)
#define tcp_hdrlen(skb) (skb->h.th->doff << 2)
#define ip_hdr(skb) (skb->nh.iph)
#define ipv6_hdr(skb) (skb->nh.ipv6h)
#define skb_network_header(skb) (skb->nh.raw)
#define skb_network_header_len(skb) (skb->h.raw - skb->nh.raw)
#define skb_network_offset(skb) (skb->nh.raw - skb->data)

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#endif
