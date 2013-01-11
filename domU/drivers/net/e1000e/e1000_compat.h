#ifndef __E1000E_COMPAT_H__
#define __E1000E_COMPAT_H__

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

/*
 * backport csum_unfold and datatypes from 2.6.25
 */
typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

static inline __wsum csum_unfold(__sum16 n)
{
    return (__force __wsum)n;
};

#ifndef CHECKSUM_PARTIAL
#define CHECKSUM_PARTIAL CHECKSUM_HW
#define CHECKSUM_COMPLETE CHECKSUM_HW
#endif

#define skb_tail_pointer(skb) skb->tail
#define skb_copy_to_linear_data_offset(skb, offset, from, len) \
    memcpy(skb->data + offset, from, len)


static inline int pci_channel_offline(struct pci_dev *pdev)
{
    return (pdev->error_state != pci_channel_io_normal);
}
#ifndef round_jiffies
#define round_jiffies(x) x
#endif

#define tcp_hdr(skb) (skb->h.th)
#define tcp_hdrlen(skb) (skb->h.th->doff << 2)
#define skb_transport_offset(skb) (skb->h.raw - skb->data)
#define skb_transport_header(skb) (skb->h.raw)
#define ipv6_hdr(skb) (skb->nh.ipv6h)
#define ip_hdr(skb) (skb->nh.iph)
#define skb_network_offset(skb) (skb->nh.raw - skb->data)

#ifndef PCI_VDEVICE
#define PCI_VDEVICE(ven, dev)        \
    PCI_VENDOR_ID_##ven, (dev),  \
    PCI_ANY_ID, PCI_ANY_ID, 0, 0
#endif

#endif 
