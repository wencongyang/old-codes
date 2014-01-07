/******************************************************************************
 * xenguest.h
 *
 * A library for guest domain management in Xen.
 *
 * Copyright (c) 2003-2004, K A Fraser.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation;
 * version 2.1 of the License.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

#ifndef XENGUEST_H
#define XENGUEST_H

#include "xs.h"

#define XCFLAGS_LIVE      1
#define XCFLAGS_DEBUG     2
#define XCFLAGS_HVM       4
#define XCFLAGS_STDVGA    8
#define X86_64_B_SIZE   64 
#define X86_32_B_SIZE   32

/* callbacks provided by xc_domain_save */
struct save_callbacks {
    int (*suspend)(void* data);
    /* callback to rendezvous with external checkpoint functions */
    int (*postcopy)(void* data);
    /* returns:
     * 0: terminate checkpointing gracefully
     * 1: take another checkpoint */
    int (*checkpoint)(void* data);

    /* Enable qemu-dm logging dirty pages to xen */
    int (*switch_qemu_logdirty)(int domid, unsigned enable, void *data); /* HVM only */

    /* called before Zero terminate is sent */
    int (*post_sendstate)(void *data);

    /* to be provided as the last argument to each callback function */
    void* data;

    /* use a thread to transfer dirty pages? */
    bool thread;
};

/**
 * This function will save a running domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm fd the file descriptor to save a domain to
 * @parm dom the id of the domain
 * @return 0 on success, -1 on failure
 */
int xc_domain_save(xc_interface *xch, int io_fd, uint32_t dom, uint32_t max_iters,
                   uint32_t max_factor, uint32_t flags /* XCFLAGS_xxx */,
                   struct save_callbacks* callbacks, int hvm);


/* pass the variable defined in xc_domain_restore() to callback. Use
 * this structure for the following purpose:
 *   1. avoid too many arguments.
 *   2. different callback implemention may need different arguments.
 *      Just add the information you need here.
 */
struct restore_data
{
    xc_interface *xch;
    uint32_t dom;
    struct domain_info_context *dinfo;
    int io_fd;
    int hvm;
    unsigned long *pfn_type;
    struct xc_mmu *mmu;
    unsigned long *p2m_frame_list;
    unsigned long *p2m;
    unsigned long console_mfn;
    unsigned long store_mfn;
};

/* callbacks provided by xc_domain_restore */
struct restore_callbacks {
    /* callback to init data */
    int (*init)(struct restore_data *comm_data, void **data);
    /* callback to free data */
    void (*free)(struct restore_data *comm_data, void *data);
    /* callback to get a buffer to store memory data that is transfered
     * from the source machine.
     */
    char *(*get_page)(struct restore_data *comm_data, void *data,
                     unsigned long pfn);
    /* callback to flush memory that is transfered from the source machine
     * to the guest. Update the guest's pagetable if necessary.
     */
    int (*flush_memory)(struct restore_data *comm_data, void *data);
    /* callback to clear a page */
    int (*hvm_clear_page)(struct restore_data *comm_data, void *data, unsigned long pfn);
    /* callback to update the guest's p2m table */
    int (*update_p2m)(struct restore_data *comm_data, void *data);
    /* callback to finish restore process. It is called before xc_domain_restore()
     * returns.
     *
     * Return value:
     *   -1: error
     *    1: success
     */
    int (*finish_restotre)(struct restore_data *comm_data, void *data);
    /* Return value:
     *   -1: error
     *    0: failover
     *    1: continue to do a checkpoint
     *    2: dirty page transmission
     *    3: resume vm and failover
     */
    int (*wait_checkpoint)(struct restore_data *comm_data, void *data);
    /* callback to resume vm before failover */
    int (*resume_vm)(struct restore_data *comm_data, void *data);

    /* xc_domain_restore() init it */
    struct restore_data comm_data;
    /* to be provided as the last argument to each callback function */
    void* data;
};

/**
 * This function will restore a saved domain.
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm fd the file descriptor to restore a domain from
 * @parm dom the id of the domain
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm hvm non-zero if this is a HVM restore
 * @parm pae non-zero if this HVM domain has PAE support enabled
 * @parm superpages non-zero to allocate guest memory with superpages
 * @return 0 on success, -1 on failure
 */
int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      unsigned int console_evtchn, unsigned long *console_mfn,
                      unsigned int hvm, unsigned int pae, int superpages,
                      struct restore_callbacks *callbacks);
/**
 * xc_domain_restore writes a file to disk that contains the device
 * model saved state.
 * The pathname of this file is XC_DEVICE_MODEL_RESTORE_FILE; The domid
 * of the new domain is automatically appended to the filename,
 * separated by a ".".
 */
#define XC_DEVICE_MODEL_RESTORE_FILE "/var/lib/xen/qemu-resume"

/**
 * This function will create a domain for a paravirtualized Linux
 * using file names pointing to kernel and ramdisk
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @parm mem_mb memory size in megabytes
 * @parm image_name name of the kernel image file
 * @parm ramdisk_name name of the ramdisk image file
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build(xc_interface *xch,
                   uint32_t domid,
                   unsigned int mem_mb,
                   const char *image_name,
                   const char *ramdisk_name,
                   const char *cmdline,
                   const char *features,
                   unsigned long flags,
                   unsigned int store_evtchn,
                   unsigned long *store_mfn,
                   unsigned int console_evtchn,
                   unsigned long *console_mfn);

/** The same interface, but the dom structure is managed by the caller */
struct xc_dom_image;
int xc_dom_linux_build(xc_interface *xch,
		       struct xc_dom_image *dom,
		       uint32_t domid,
		       unsigned int mem_mb,
		       const char *image_name,
		       const char *ramdisk_name,
		       unsigned long flags,
		       unsigned int store_evtchn,
		       unsigned long *store_mfn,
		       unsigned int console_evtchn,
		       unsigned long *console_mfn);

/**
 * This function will create a domain for a paravirtualized Linux
 * using buffers for kernel and initrd
 *
 * @parm xch a handle to an open hypervisor interface
 * @parm domid the id of the domain
 * @parm mem_mb memory size in megabytes
 * @parm image_buffer buffer containing kernel image
 * @parm image_size size of the kernel image buffer
 * @parm initrd_buffer name of the ramdisk image file
 * @parm initrd_size size of the ramdisk buffer
 * @parm cmdline command line string
 * @parm flags domain creation flags
 * @parm store_evtchn the store event channel for this domain to use
 * @parm store_mfn returned with the mfn of the store page
 * @parm console_evtchn the console event channel for this domain to use
 * @parm conole_mfn returned with the mfn of the console page
 * @return 0 on success, -1 on failure
 */
int xc_linux_build_mem(xc_interface *xch,
                       uint32_t domid,
                       unsigned int mem_mb,
                       const char *image_buffer,
                       unsigned long image_size,
                       const char *initrd_buffer,
                       unsigned long initrd_size,
                       const char *cmdline,
                       const char *features,
                       unsigned long flags,
                       unsigned int store_evtchn,
                       unsigned long *store_mfn,
                       unsigned int console_evtchn,
                       unsigned long *console_mfn);

int xc_hvm_build(xc_interface *xch,
                 uint32_t domid,
                 int memsize,
                 const char *image_name);

int xc_hvm_build_target_mem(xc_interface *xch,
                            uint32_t domid,
                            int memsize,
                            int target,
                            const char *image_name);

int xc_hvm_build_mem(xc_interface *xch,
                     uint32_t domid,
                     int memsize,
                     const char *image_buffer,
                     unsigned long image_size);

int xc_suspend_evtchn_release(xc_interface *xch, xc_evtchn *xce, int domid, int suspend_evtchn);

int xc_suspend_evtchn_init(xc_interface *xch, xc_evtchn *xce, int domid, int port);

int xc_await_suspend(xc_interface *xch, xc_evtchn *xce, int suspend_evtchn);

int xc_get_bit_size(xc_interface *xch,
                    const char *image_name, const char *cmdline,
                    const char *features, int *type);

int xc_mark_page_online(xc_interface *xch, unsigned long start,
                        unsigned long end, uint32_t *status);

int xc_mark_page_offline(xc_interface *xch, unsigned long start,
                          unsigned long end, uint32_t *status);

int xc_query_page_offline_status(xc_interface *xch, unsigned long start,
                                 unsigned long end, uint32_t *status);

int xc_exchange_page(xc_interface *xch, int domid, xen_pfn_t mfn);

int xc_suspend_qemu(xc_interface *xch, struct xs_handle* xsh, int domid);


/**
 * This function map m2p table
 * @parm xch a handle to an open hypervisor interface
 * @parm max_mfn the max pfn
 * @parm prot the flags to map, such as read/write etc
 * @parm mfn0 return the first mfn, can be NULL
 * @return mapped m2p table on success, NULL on failure
 */
xen_pfn_t *xc_map_m2p(xc_interface *xch,
                      unsigned long max_mfn,
                      int prot,
                      unsigned long *mfn0);
#endif /* XENGUEST_H */
