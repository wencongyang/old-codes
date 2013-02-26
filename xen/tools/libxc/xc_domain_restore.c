/******************************************************************************
 * xc_domain_restore.c
 *
 * Restore the state of a guest session.
 *
 * Copyright (c) 2003, K A Fraser.
 * Copyright (c) 2006, Intel Corporation
 * Copyright (c) 2007, XenSource Inc.
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
 *
 */

#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <inttypes.h>

#include "xg_private.h"
#include "xg_save_restore.h"
#include "xc_dom.h"

#include <xen/hvm/ioreq.h>
#include <xen/hvm/params.h>
#include <xs.h>

#define NR_wait_resume	312
#define NR_reset_suspend_count 314
//xen_pfn_t dirty_mfn[100000];
//int dirty_err[100000];

struct restore_ctx {
    unsigned long max_mfn; /* max mfn of the current host machine */
    unsigned long hvirt_start; /* virtual starting address of the hypervisor */
    unsigned int pt_levels; /* #levels of page tables used by the current guest */
    unsigned long nr_pfns; /* number of 'in use' pfns in the guest (i.e. #P2M entries with a valid mfn) */
    xen_pfn_t *live_p2m; /* Live mapping of the table mapping each PFN to its current MFN. */
    xen_pfn_t *p2m; /* A table mapping each PFN to its new MFN. */
    xen_pfn_t *p2m_batch; /* A table of P2M mappings in the current region.  */
    int completed; /* Set when a consistent image is available */
    int last_checkpoint; /* Set when we should commit to the current checkpoint when it completes. */
    struct domain_info_context dinfo;
};

#define HEARTBEAT_MS 1000

#ifndef __MINIOS__
static ssize_t rdexact(xc_interface *xch, struct restore_ctx *ctx,
                       int fd, void* buf, size_t size)
{
    size_t offset = 0;
    ssize_t len;
    struct timeval tv;
    fd_set rfds;

    while ( offset < size )
    {
        if ( ctx->completed ) {
            /* expect a heartbeat every HEARBEAT_MS ms maximum */
            tv.tv_sec = HEARTBEAT_MS / 1000;
            tv.tv_usec = (HEARTBEAT_MS % 1000) * 1000;

            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            len = select(fd + 1, &rfds, NULL, NULL, &tv);
            if ( len == -1 && errno == EINTR )
                continue;
            if ( !FD_ISSET(fd, &rfds) ) {
                ERROR("read_exact_timed failed (select returned %zd)", len);
                errno = ETIMEDOUT;
                return -1;
            }
        }

        len = read(fd, buf + offset, size - offset);
        if ( (len == -1) && ((errno == EINTR) || (errno == EAGAIN)) )
            continue;
        if ( len == 0 ) {
            ERROR("0-length read");
            errno = 0;
        }
        if ( len <= 0 ) {
            ERROR("read_exact_timed failed (read rc: %d, errno: %d)", len, errno);
            return -1;
        }
        offset += len;
    }

    return 0;
}

#define RDEXACT(fd,buf,size) rdexact(xch, ctx, fd, buf, size)
#else
#define RDEXACT read_exact
#endif
/*
** In the state file (or during transfer), all page-table pages are
** converted into a 'canonical' form where references to actual mfns
** are replaced with references to the corresponding pfns.
** This function inverts that operation, replacing the pfn values with
** the (now known) appropriate mfn values.
*/
static int uncanonicalize_pagetable(
    xc_interface *xch, uint32_t dom, struct restore_ctx *ctx, void *page)
{
    int i, pte_last, nr_mfns = 0;
    unsigned long pfn;
    uint64_t pte;
    struct domain_info_context *dinfo = &ctx->dinfo;

    pte_last = PAGE_SIZE / ((ctx->pt_levels == 2)? 4 : 8);

    /* First pass: work out how many (if any) MFNs we need to alloc */
    for ( i = 0; i < pte_last; i++ )
    {
        if ( ctx->pt_levels == 2 )
            pte = ((uint32_t *)page)[i];
        else
            pte = ((uint64_t *)page)[i];

        /* XXX SMH: below needs fixing for PROT_NONE etc */
        if ( !(pte & _PAGE_PRESENT) )
            continue;
        
        pfn = (pte >> PAGE_SHIFT) & MFN_MASK_X86;
        
        if ( pfn >= dinfo->p2m_size )
        {
            /* This "page table page" is probably not one; bail. */
            ERROR("Frame number in page table is out of range: "
                  "i=%d pfn=0x%lx p2m_size=%lu",
                  i, pfn, dinfo->p2m_size);
            return 0;
        }
        
        if ( ctx->p2m[pfn] == INVALID_P2M_ENTRY )
        {
            /* Have a 'valid' PFN without a matching MFN - need to alloc */
            ctx->p2m_batch[nr_mfns++] = pfn; 
            ctx->p2m[pfn]--;
        }
    }

    /* Allocate the requisite number of mfns. */
    if ( nr_mfns &&
         (xc_domain_populate_physmap_exact(xch, dom, nr_mfns, 0, 0,
                                            ctx->p2m_batch) != 0) )
    { 
        ERROR("Failed to allocate memory for batch.!\n"); 
        errno = ENOMEM;
        return 0; 
    }
    
    /* Second pass: uncanonicalize each present PTE */
    nr_mfns = 0;
    for ( i = 0; i < pte_last; i++ )
    {
        if ( ctx->pt_levels == 2 )
            pte = ((uint32_t *)page)[i];
        else
            pte = ((uint64_t *)page)[i];
        
        /* XXX SMH: below needs fixing for PROT_NONE etc */
        if ( !(pte & _PAGE_PRESENT) )
            continue;
        
        pfn = (pte >> PAGE_SHIFT) & MFN_MASK_X86;

        if ( ctx->p2m[pfn] == (INVALID_P2M_ENTRY-1) )
            ctx->p2m[pfn] = ctx->p2m_batch[nr_mfns++];

        pte &= ~MADDR_MASK_X86;
        pte |= (uint64_t)ctx->p2m[pfn] << PAGE_SHIFT;

        if ( ctx->pt_levels == 2 )
            ((uint32_t *)page)[i] = (uint32_t)pte;
        else
            ((uint64_t *)page)[i] = (uint64_t)pte;
    }

    return 1;
}


/* Load the p2m frame list, plus potential extended info chunk */
static xen_pfn_t *load_p2m_frame_list(
    xc_interface *xch, struct restore_ctx *ctx,
    int io_fd, int *pae_extended_cr3, int *ext_vcpucontext,
    int *vcpuextstate, uint32_t *vcpuextstate_size)
{
    xen_pfn_t *p2m_frame_list;
    vcpu_guest_context_any_t ctxt;
    xen_pfn_t p2m_fl_zero;
    struct domain_info_context *dinfo = &ctx->dinfo;

    /* Read first entry of P2M list, or extended-info signature (~0UL). */
    if ( RDEXACT(io_fd, &p2m_fl_zero, sizeof(long)) )
    {
        PERROR("read extended-info signature failed");
        return NULL;
    }
    
    if ( p2m_fl_zero == ~0UL )
    {
        uint32_t tot_bytes;
        
        /* Next 4 bytes: total size of following extended info. */
        if ( RDEXACT(io_fd, &tot_bytes, sizeof(tot_bytes)) )
        {
            PERROR("read extended-info size failed");
            return NULL;
        }
        
        while ( tot_bytes )
        {
            uint32_t chunk_bytes;
            char     chunk_sig[4];
            
            /* 4-character chunk signature + 4-byte remaining chunk size. */
            if ( RDEXACT(io_fd, chunk_sig, sizeof(chunk_sig)) ||
                 RDEXACT(io_fd, &chunk_bytes, sizeof(chunk_bytes)) ||
                 (tot_bytes < (chunk_bytes + 8)) )
            {
                PERROR("read extended-info chunk signature failed");
                return NULL;
            }
            tot_bytes -= 8;

            /* VCPU context structure? */
            if ( !strncmp(chunk_sig, "vcpu", 4) )
            {
                /* Pick a guest word-size and PT depth from the ctxt size */
                if ( chunk_bytes == sizeof (ctxt.x32) )
                {
                    dinfo->guest_width = 4;
                    if ( ctx->pt_levels > 2 ) 
                        ctx->pt_levels = 3; 
                }
                else if ( chunk_bytes == sizeof (ctxt.x64) )
                {
                    dinfo->guest_width = 8;
                    ctx->pt_levels = 4;
                }
                else 
                {
                    ERROR("bad extended-info context size %d", chunk_bytes);
                    return NULL;
                }

                if ( RDEXACT(io_fd, &ctxt, chunk_bytes) )
                {
                    PERROR("read extended-info vcpu context failed");
                    return NULL;
                }
                tot_bytes -= chunk_bytes;
                chunk_bytes = 0;

                if ( GET_FIELD(&ctxt, vm_assist) 
                     & (1UL << VMASST_TYPE_pae_extended_cr3) )
                    *pae_extended_cr3 = 1;
            }
            else if ( !strncmp(chunk_sig, "extv", 4) )
            {
                *ext_vcpucontext = 1;
            }
            else if ( !strncmp(chunk_sig, "xcnt", 4) )
            {
                *vcpuextstate = 1;
                RDEXACT(io_fd, vcpuextstate_size, sizeof(*vcpuextstate_size));
                tot_bytes -= chunk_bytes;
                chunk_bytes = 0;
            }
            
            /* Any remaining bytes of this chunk: read and discard. */
            while ( chunk_bytes )
            {
                unsigned long sz = MIN(chunk_bytes, sizeof(xen_pfn_t));
                if ( RDEXACT(io_fd, &p2m_fl_zero, sz) )
                {
                    PERROR("read-and-discard extended-info chunk bytes failed");
                    return NULL;
                }
                chunk_bytes -= sz;
                tot_bytes   -= sz;
            }
        }

        /* Now read the real first entry of P2M list. */
        if ( RDEXACT(io_fd, &p2m_fl_zero, sizeof(xen_pfn_t)) )
        {
            PERROR("read first entry of p2m_frame_list failed");
            return NULL;
        }
    }

    /* Now that we know the guest's word-size, can safely allocate 
     * the p2m frame list */
    if ( (p2m_frame_list = malloc(P2M_TOOLS_FL_SIZE)) == NULL )
    {
        ERROR("Couldn't allocate p2m_frame_list array");
        return NULL;
    }

    /* First entry has already been read. */
    p2m_frame_list[0] = p2m_fl_zero;
    if ( RDEXACT(io_fd, &p2m_frame_list[1], 
                 (P2M_FL_ENTRIES - 1) * sizeof(xen_pfn_t)) )
    {
        PERROR("read p2m_frame_list failed");
        return NULL;
    }
    
    return p2m_frame_list;
}

typedef struct {
    int ishvm;
    union {
        struct tailbuf_pv {
            unsigned int pfncount;
            unsigned long* pfntab;
            unsigned int vcpucount;
            unsigned char* vcpubuf;
            unsigned char shared_info_page[PAGE_SIZE];
        } pv;
        struct tailbuf_hvm {
            uint64_t magicpfns[3];
            uint32_t hvmbufsize, reclen;
            uint8_t* hvmbuf;
            struct {
                uint32_t magic;
                uint32_t version;
                uint64_t len;
            } qemuhdr;
            uint32_t qemubufsize;
            uint8_t* qemubuf;
        } hvm;
    } u;
} tailbuf_t;

/* read stream until EOF, growing buffer as necssary */
static int compat_buffer_qemu(xc_interface *xch, struct restore_ctx *ctx,
                              int fd, struct tailbuf_hvm *buf)
{
    uint8_t *qbuf, *tmp;
    int blen = 0, dlen = 0;
    int rc;

    /* currently save records tend to be about 7K */
    blen = 8192;
    if ( !(qbuf = malloc(blen)) ) {
        ERROR("Error allocating QEMU buffer");
        return -1;
    }

    while( (rc = read(fd, qbuf+dlen, blen-dlen)) > 0 ) {
        DPRINTF("Read %d bytes of QEMU data\n", rc);
        dlen += rc;

        if (dlen == blen) {
            DPRINTF("%d-byte QEMU buffer full, reallocating...\n", dlen);
            blen += 4096;
            tmp = realloc(qbuf, blen);
            if ( !tmp ) {
                ERROR("Error growing QEMU buffer to %d bytes", blen);
                free(qbuf);
                return -1;
            }
            qbuf = tmp;
        }
    }

    if ( rc < 0 ) {
        ERROR("Error reading QEMU data");
        free(qbuf);
        return -1;
    }

    if ( memcmp(qbuf, "QEVM", 4) ) {
        ERROR("Invalid QEMU magic: 0x%08x", *(unsigned long*)qbuf);
        free(qbuf);
        return -1;
    }

    buf->qemubuf = qbuf;
    buf->qemubufsize = dlen;

    return 0;
}

static int buffer_qemu(xc_interface *xch, struct restore_ctx *ctx,
                       int fd, struct tailbuf_hvm *buf)
{
    uint32_t qlen;
    uint8_t *tmp;

    if ( RDEXACT(fd, &qlen, sizeof(qlen)) ) {
        PERROR("Error reading QEMU header length");
        return -1;
    }

    if ( qlen > buf->qemubufsize ) {
        if ( buf->qemubuf) {
            tmp = realloc(buf->qemubuf, qlen);
            if ( tmp )
                buf->qemubuf = tmp;
            else {
                ERROR("Error reallocating QEMU state buffer");
                return -1;
            }
        } else {
            buf->qemubuf = malloc(qlen);
            if ( !buf->qemubuf ) {
                ERROR("Error allocating QEMU state buffer");
                return -1;
            }
        }
    }
    buf->qemubufsize = qlen;

    if ( RDEXACT(fd, buf->qemubuf, buf->qemubufsize) ) {
        PERROR("Error reading QEMU state");
        return -1;
    }

    return 0;
}

static int dump_qemu(xc_interface *xch, uint32_t dom, struct tailbuf_hvm *buf)
{
    int saved_errno;
    char path[256];
    FILE *fp;

    sprintf(path, XC_DEVICE_MODEL_RESTORE_FILE".%u", dom);
    fp = fopen(path, "wb");
    if ( !fp )
        return -1;

    DPRINTF("Writing %d bytes of QEMU data\n", buf->qemubufsize);
    if ( fwrite(buf->qemubuf, 1, buf->qemubufsize, fp) != buf->qemubufsize) {
        saved_errno = errno;
        fclose(fp);
        errno = saved_errno;
        return -1;
    }

    fclose(fp);

    return 0;
}

static int buffer_tail_hvm(xc_interface *xch, struct restore_ctx *ctx,
                           struct tailbuf_hvm *buf, int fd,
                           unsigned int max_vcpu_id, uint64_t vcpumap,
                           int ext_vcpucontext,
                           int vcpuextstate, uint32_t vcpuextstate_size)
{
    uint8_t *tmp;
    unsigned char qemusig[21];

    if ( RDEXACT(fd, buf->magicpfns, sizeof(buf->magicpfns)) ) {
        PERROR("Error reading magic PFNs");
        return -1;
    }

    if ( RDEXACT(fd, &buf->reclen, sizeof(buf->reclen)) ) {
        PERROR("Error reading HVM params size");
        return -1;
    }

    if ( buf->reclen > buf->hvmbufsize ) {
        if ( buf->hvmbuf) {
            tmp = realloc(buf->hvmbuf, buf->reclen);
            if ( tmp ) {
                buf->hvmbuf = tmp;
                buf->hvmbufsize = buf->reclen;
            } else {
                ERROR("Error reallocating HVM param buffer");
                return -1;
            }
        } else {
            buf->hvmbuf = malloc(buf->reclen);
            if ( !buf->hvmbuf ) {
                ERROR("Error allocating HVM param buffer");
                return -1;
            }
            buf->hvmbufsize = buf->reclen;
        }
    }

    if ( RDEXACT(fd, buf->hvmbuf, buf->reclen) ) {
        PERROR("Error reading HVM params");
        return -1;
    }

    if ( RDEXACT(fd, qemusig, sizeof(qemusig)) ) {
        PERROR("Error reading QEMU signature");
        return -1;
    }

    /* The legacy live-migration QEMU record has no length information.
     * Short of reimplementing the QEMU parser, we're forced to just read
     * until EOF.
     *
     * Gets around this by sending a different signatures for the new
     * live-migration QEMU record and Remus which includes a length
     * prefix
     */
    if ( !memcmp(qemusig, "QemuDeviceModelRecord", sizeof(qemusig)) )
        return compat_buffer_qemu(xch, ctx, fd, buf);
    else if ( !memcmp(qemusig, "DeviceModelRecord0002", sizeof(qemusig)) ||
              !memcmp(qemusig, "RemusDeviceModelState", sizeof(qemusig)) )
        return buffer_qemu(xch, ctx, fd, buf);

    qemusig[20] = '\0';
    ERROR("Invalid QEMU signature: %s", qemusig);
    return -1;
}

static int buffer_tail_pv(xc_interface *xch, struct restore_ctx *ctx,
                          struct tailbuf_pv *buf, int fd,
                          unsigned int max_vcpu_id, uint64_t vcpumap,
                          int ext_vcpucontext,
                          int vcpuextstate,
                          uint32_t vcpuextstate_size)
{
    unsigned int i;
    size_t pfnlen, vcpulen;
    struct domain_info_context *dinfo = &ctx->dinfo;

    /* TODO: handle changing pfntab and vcpu counts */
    /* PFN tab */
    if ( RDEXACT(fd, &buf->pfncount, sizeof(buf->pfncount)) ||
         (buf->pfncount > (1U << 28)) ) /* up to 1TB of address space */
    {
        PERROR("Error when reading pfn count");
        return -1;
    }
    pfnlen = sizeof(unsigned long) * buf->pfncount;
    if ( !(buf->pfntab) ) {
        if ( !(buf->pfntab = malloc(pfnlen)) ) {
            ERROR("Error allocating PFN tail buffer");
            return -1;
        }
    }
    // DPRINTF("Reading PFN tab: %d bytes\n", pfnlen);
    if ( RDEXACT(fd, buf->pfntab, pfnlen) ) {
        PERROR("Error when reading pfntab");
        goto free_pfntab;
    }

    /* VCPU contexts */
    buf->vcpucount = 0;
    for (i = 0; i <= max_vcpu_id; i++) {
        // DPRINTF("vcpumap: %llx, cpu: %d, bit: %llu\n", vcpumap, i, (vcpumap % (1ULL << i)));
        if ( (!(vcpumap & (1ULL << i))) )
            continue;
        buf->vcpucount++;
    }
    // DPRINTF("VCPU count: %d\n", buf->vcpucount);
    vcpulen = ((dinfo->guest_width == 8) ? sizeof(vcpu_guest_context_x86_64_t)
               : sizeof(vcpu_guest_context_x86_32_t)) * buf->vcpucount;
    if ( ext_vcpucontext )
        vcpulen += 128 * buf->vcpucount;
    if ( vcpuextstate ) {
        vcpulen += vcpuextstate_size * buf->vcpucount;
    }

    if ( !(buf->vcpubuf) ) {
        if ( !(buf->vcpubuf = malloc(vcpulen)) ) {
            ERROR("Error allocating VCPU ctxt tail buffer");
            goto free_pfntab;
        }
    }
    // DPRINTF("Reading VCPUS: %d bytes\n", vcpulen);
    if ( RDEXACT(fd, buf->vcpubuf, vcpulen) ) {
        PERROR("Error when reading ctxt");
        goto free_vcpus;
    }

    /* load shared_info_page */
    // DPRINTF("Reading shared info: %lu bytes\n", PAGE_SIZE);
    if ( RDEXACT(fd, buf->shared_info_page, PAGE_SIZE) ) {
        PERROR("Error when reading shared info page");
        goto free_vcpus;
    }

    return 0;

  free_vcpus:
    if (buf->vcpubuf) {
        free (buf->vcpubuf);
        buf->vcpubuf = NULL;
    }
  free_pfntab:
    if (buf->pfntab) {
        free (buf->pfntab);
        buf->pfntab = NULL;
    }

    return -1;
}

static int buffer_tail(xc_interface *xch, struct restore_ctx *ctx,
                       tailbuf_t *buf, int fd, unsigned int max_vcpu_id,
                       uint64_t vcpumap, int ext_vcpucontext,
                       int vcpuextstate, uint32_t vcpuextstate_size)
{
    if ( buf->ishvm )
        return buffer_tail_hvm(xch, ctx, &buf->u.hvm, fd, max_vcpu_id, vcpumap,
                               ext_vcpucontext, vcpuextstate,
                               vcpuextstate_size);
    else
        return buffer_tail_pv(xch, ctx, &buf->u.pv, fd, max_vcpu_id, vcpumap,
                              ext_vcpucontext, vcpuextstate,
                              vcpuextstate_size);
}

static void tailbuf_free_hvm(struct tailbuf_hvm *buf)
{
    if ( buf->hvmbuf ) {
        free(buf->hvmbuf);
        buf->hvmbuf = NULL;
    }
    if ( buf->qemubuf ) {
        free(buf->qemubuf);
        buf->qemubuf = NULL;
    }
}

static void tailbuf_free_pv(struct tailbuf_pv *buf)
{
    if ( buf->vcpubuf ) {
        free(buf->vcpubuf);
        buf->vcpubuf = NULL;
    }
    if ( buf->pfntab ) {
        free(buf->pfntab);
        buf->pfntab = NULL;
    }
}

static void tailbuf_free(tailbuf_t *buf)
{
    if ( buf->ishvm )
        tailbuf_free_hvm(&buf->u.hvm);
    else
        tailbuf_free_pv(&buf->u.pv);
}

typedef struct {
    void* pages;
    /* pages is of length nr_physpages, pfn_types is of length nr_pages */
    unsigned int nr_physpages, nr_pages;

    /* Types of the pfns in the current region */
    unsigned long* pfn_types;

    int verify;

    int new_ctxt_format;
    int max_vcpu_id;
    uint64_t vcpumap;
    uint64_t identpt;
    uint64_t vm86_tss;
    uint64_t console_pfn;
    uint64_t acpi_ioport_location;
} pagebuf_t;

static int pagebuf_init(pagebuf_t* buf)
{
    memset(buf, 0, sizeof(*buf));
    return 0;
}

static void pagebuf_free(pagebuf_t* buf)
{
    if (buf->pages) {
        free(buf->pages);
        buf->pages = NULL;
    }
    if(buf->pfn_types) {
        free(buf->pfn_types);
        buf->pfn_types = NULL;
    }
}

static int pagebuf_get_one(xc_interface *xch, struct restore_ctx *ctx,
                           pagebuf_t* buf, int fd, uint32_t dom)
{
    int count, countpages, oldcount, i;
    void* ptmp;
    //struct timeval time;
    //FILE *fp = fopen("/root/yewei/4.txt", "at");

    if ( RDEXACT(fd, &count, sizeof(count)) )
    {
        PERROR("Error when reading batch size");
        return -1;
    }

    // DPRINTF("reading batch of %d pages\n", count);

    switch ( count )
    {
    case 0:
        // DPRINTF("Last batch read\n");
	//fprintf(fp, "Last batch read\n");
	//fclose(fp);
        return 0;

    case XC_SAVE_ID_ENABLE_VERIFY_MODE:
	//fprintf(fp, "XC_SAVE_ID_ENABLE_VERIFY_MODE\n");
	//fclose(fp);
        //DPRINTF("Entering page verify mode\n");
        buf->verify = 1;
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_VCPU_INFO:
	//fprintf(fp, "XC_SAVE_ID_VCPU_INFO\n");
	//fclose(fp);
        buf->new_ctxt_format = 1;
        if ( RDEXACT(fd, &buf->max_vcpu_id, sizeof(buf->max_vcpu_id)) ||
             buf->max_vcpu_id >= 64 || RDEXACT(fd, &buf->vcpumap,
                                               sizeof(uint64_t)) ) {
	    //fprintf(fp, "Error when reading max_vcpu_id\n");
	    //fflush(fp);
            PERROR("Error when reading max_vcpu_id");
            return -1;
        }
        // DPRINTF("Max VCPU ID: %d, vcpumap: %llx\n", buf->max_vcpu_id, buf->vcpumap);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_HVM_IDENT_PT:
	//fprintf(fp, "XC_SAVE_ID_HVM_IDENT_PT\n");
	//fclose(fp);
        /* Skip padding 4 bytes then read the EPT identity PT location. */
        if ( RDEXACT(fd, &buf->identpt, sizeof(uint32_t)) ||
             RDEXACT(fd, &buf->identpt, sizeof(uint64_t)) )
        {
            PERROR("error read the address of the EPT identity map");
            return -1;
        }
        // DPRINTF("EPT identity map address: %llx\n", buf->identpt);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_HVM_VM86_TSS:
	//fprintf(fp, "XC_SAVE_ID_HVM_VM86_TSS\n");
	//fclose(fp);
        /* Skip padding 4 bytes then read the vm86 TSS location. */
        if ( RDEXACT(fd, &buf->vm86_tss, sizeof(uint32_t)) ||
             RDEXACT(fd, &buf->vm86_tss, sizeof(uint64_t)) )
        {
            PERROR("error read the address of the vm86 TSS");
            return -1;
        }
        // DPRINTF("VM86 TSS location: %llx\n", buf->vm86_tss);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_TMEM:
    	//gettimeofday(&time, NULL);
    	//fprintf(fp, "[%d.%d]begin xc_tmem_restore\n", (int)time.tv_sec, (int)time.tv_usec);
        //fflush(fp);
	//DPRINTF("xc_domain_restore start tmem\n");
        if ( xc_tmem_restore(xch, dom, fd) ) {
            PERROR("error reading/restoring tmem");
            return -1;
        }
    	//gettimeofday(&time, NULL);
    	//fprintf(fp, "[%d.%d]done\n", (int)time.tv_sec, (int)time.tv_usec);
	//fflush(fp);
	//fclose(fp);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_TMEM_EXTRA:
    	//gettimeofday(&time, NULL);
    	//fprintf(fp, "[%d.%d]begin xc_tmem_tmem_extra\n", (int)time.tv_sec, (int)time.tv_usec);
        //fflush(fp);
        if ( xc_tmem_restore_extra(xch, dom, fd) ) {
            PERROR("error reading/restoring tmem extra");
            return -1;
        }
    	//gettimeofday(&time, NULL);
    	//fprintf(fp, "[%d.%d]done\n", (int)time.tv_sec, (int)time.tv_usec);
	//fflush(fp);
	//fclose(fp);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_TSC_INFO:
    {
        uint32_t tsc_mode, khz, incarn;
        uint64_t nsec;
	//fprintf(fp, "XC_SAVE_ID_TSC_INFO\n");
	//fclose(fp);
    	//gettimeofday(&time, NULL);
    	//fprintf(fp, "[%d.%d]begin tsc\n", (int)time.tv_sec, (int)time.tv_usec);
	//fflush(fp);
        if ( RDEXACT(fd, &tsc_mode, sizeof(uint32_t)) ||
             RDEXACT(fd, &nsec, sizeof(uint64_t)) ||
             RDEXACT(fd, &khz, sizeof(uint32_t)) ||
             RDEXACT(fd, &incarn, sizeof(uint32_t)) ||
             xc_domain_set_tsc_info(xch, dom, tsc_mode, nsec, khz, incarn) ) {
	    //fprintf(fp, "error reading/restore tsc info\n");
	    //fflush(fp);
            PERROR("error reading/restoring tsc info");
            return -1;
        }
    	//gettimeofday(&time, NULL);
    	//fprintf(fp, "[%d.%d]done\n", (int)time.tv_sec, (int)time.tv_usec);
	//fflush(fp);
	//fclose(fp);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);
    }

    case XC_SAVE_ID_HVM_CONSOLE_PFN :
	//fprintf(fp, "XC_SAVE_ID_HVM_CONSOLE_PFN\n");
	//fclose(fp);
        /* Skip padding 4 bytes then read the console pfn location. */
        if ( RDEXACT(fd, &buf->console_pfn, sizeof(uint32_t)) ||
             RDEXACT(fd, &buf->console_pfn, sizeof(uint64_t)) )
        {
            PERROR("error read the address of the console pfn");
            return -1;
        }
        // DPRINTF("console pfn location: %llx\n", buf->console_pfn);
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_LAST_CHECKPOINT:
	//fprintf(fp, "XC_SAVE_ID_LAST_CHECKPOINT\n");
	//fclose(fp);
        ctx->last_checkpoint = 1;
        // DPRINTF("last checkpoint indication received");
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    case XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION:
	//fprintf(fp, "XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION\n");
	//fclose(fp);
        /* Skip padding 4 bytes then read the acpi ioport location. */
        if ( RDEXACT(fd, &buf->acpi_ioport_location, sizeof(uint32_t)) ||
             RDEXACT(fd, &buf->acpi_ioport_location, sizeof(uint64_t)) )
        {
            PERROR("error read the acpi ioport location");
            return -1;
        }
        return pagebuf_get_one(xch, ctx, buf, fd, dom);

    default:
	//fprintf(fp, "batch size = %d\n", count);
        if ( (count > MAX_BATCH_SIZE) || (count < 0) ) {
            ERROR("Max batch size exceeded (%d). Giving up.", count);
            errno = EMSGSIZE;
            return -1;
        }
        break;
    }

    oldcount = buf->nr_pages;
    buf->nr_pages += count;
    if (!buf->pfn_types) {
        if (!(buf->pfn_types = malloc(buf->nr_pages * sizeof(*(buf->pfn_types))))) {
            ERROR("Could not allocate PFN type buffer");
            return -1;
        }
    } else {
        if (!(ptmp = realloc(buf->pfn_types, buf->nr_pages * sizeof(*(buf->pfn_types))))) {
            ERROR("Could not reallocate PFN type buffer");
            return -1;
        }
        buf->pfn_types = ptmp;
    }
    if ( RDEXACT(fd, buf->pfn_types + oldcount, count * sizeof(*(buf->pfn_types)))) {
        //fprintf(fp, "Error when reading redion pfn types\n");
	//fflush(fp);
	PERROR("Error when reading region pfn types");
        return -1;
    }

    countpages = count;
    for (i = oldcount; i < buf->nr_pages; ++i)
        if ((buf->pfn_types[i] & XEN_DOMCTL_PFINFO_LTAB_MASK) == XEN_DOMCTL_PFINFO_XTAB)
            --countpages;

    if (!countpages)
        return count;

    oldcount = buf->nr_physpages;
    buf->nr_physpages += countpages;
    if (!buf->pages) {
        if (!(buf->pages = malloc(buf->nr_physpages * PAGE_SIZE))) {
            ERROR("Could not allocate page buffer");
            return -1;
        }
    } else {
        if (!(ptmp = realloc(buf->pages, buf->nr_physpages * PAGE_SIZE))) {
            ERROR("Could not reallocate page buffer");
            return -1;
        }
        buf->pages = ptmp;
    }
    if ( RDEXACT(fd, buf->pages + oldcount * PAGE_SIZE, countpages * PAGE_SIZE) ) {
	//fprintf(fp, "Error when reading pages\n");
	//fflush(fp);
        PERROR("Error when reading pages");
        return -1;
    }

	//fclose(fp);
    return count;
}

static int pagebuf_get(xc_interface *xch, struct restore_ctx *ctx,
                       pagebuf_t* buf, int fd, uint32_t dom)
{
    int rc;

    buf->nr_physpages = buf->nr_pages = 0;

    do {
        rc = pagebuf_get_one(xch, ctx, buf, fd, dom);
    } while (rc > 0);

    if (rc < 0)
        pagebuf_free(buf);

    return rc;
}

#define BITS_PER_LONG (sizeof(unsigned long) * 8)
#define BITS_TO_LONGS(bits) (((bits)+BITS_PER_LONG-1)/BITS_PER_LONG)
#define BITMAP_SIZE   (BITS_TO_LONGS(dinfo->p2m_size) * sizeof(unsigned long))

#define BITMAP_ENTRY(_nr,_bmap) \
   ((volatile unsigned long *)(_bmap))[(_nr)/BITS_PER_LONG]

#define BITMAP_SHIFT(_nr) ((_nr) % BITS_PER_LONG)

#define ORDER_LONG (sizeof(unsigned long) == 4 ? 5 : 6)

static inline int test_bit (int nr, volatile void * addr)
{
    return (BITMAP_ENTRY(nr, addr) >> BITMAP_SHIFT(nr)) & 1;
}

static inline void clear_bit (int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) &= ~(1UL << BITMAP_SHIFT(nr));
}

static inline void set_bit ( int nr, volatile void * addr)
{
    BITMAP_ENTRY(nr, addr) |= (1UL << BITMAP_SHIFT(nr));
}

int first_time = 1;
char* pagebase = NULL;
DECLARE_HYPERCALL_BUFFER(unsigned long, to_send);
static int apply_batch(xc_interface *xch, uint32_t dom, struct restore_ctx *ctx,
                       xen_pfn_t* region_mfn, unsigned long* pfn_type, int pae_extended_cr3,
                       unsigned int hvm, struct xc_mmu* mmu,
                       pagebuf_t* pagebuf, int curbatch)
{
    int i, j, curpage, nr_mfns;
    /* used by debug verify code */
    unsigned long buf[PAGE_SIZE/sizeof(unsigned long)];
    /* Our mapping of the current region (batch) */
    char *region_base = NULL;
    /* A temporary mapping, and a copy, of one frame of guest memory. */
    unsigned long *page = NULL;
    int nraces = 0;
    struct domain_info_context *dinfo = &ctx->dinfo;
    //int* pfn_err = NULL;
    int rc = -1;

    unsigned long mfn, pfn, pagetype;

    j = pagebuf->nr_pages - curbatch;
    if (j > MAX_BATCH_SIZE)
        j = MAX_BATCH_SIZE;

    /* First pass for this batch: work out how much memory to alloc */
    nr_mfns = 0; 
    for ( i = 0; i < j; i++ )
    {
        unsigned long pfn, pagetype;
        pfn      = pagebuf->pfn_types[i + curbatch] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
        pagetype = pagebuf->pfn_types[i + curbatch] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

        if ( (pagetype != XEN_DOMCTL_PFINFO_XTAB) && 
             (ctx->p2m[pfn] == INVALID_P2M_ENTRY) )
        {
            /* Have a live PFN which hasn't had an MFN allocated */
            ctx->p2m_batch[nr_mfns++] = pfn; 
            ctx->p2m[pfn]--;
        }
    } 

    /* Now allocate a bunch of mfns for this batch */
    if ( nr_mfns &&
         (xc_domain_populate_physmap_exact(xch, dom, nr_mfns, 0,
                                            0, ctx->p2m_batch) != 0) )
    { 
        ERROR("Failed to allocate memory for batch.!\n"); 
        errno = ENOMEM;
        return -1;
    }

    /* Second pass for this batch: update p2m[] and region_mfn[] */
    nr_mfns = 0; 
    for ( i = 0; i < j; i++ )
    {
        unsigned long pfn, pagetype;
        pfn      = pagebuf->pfn_types[i + curbatch] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
        pagetype = pagebuf->pfn_types[i + curbatch] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

	set_bit(pfn, to_send);
        if ( pagetype == XEN_DOMCTL_PFINFO_XTAB )
            region_mfn[i] = ~0UL; /* map will fail but we don't care */
        else 
        {
            if ( ctx->p2m[pfn] == (INVALID_P2M_ENTRY-1) )
            {
                /* We just allocated a new mfn above; update p2m */
                ctx->p2m[pfn] = ctx->p2m_batch[nr_mfns++]; 
                ctx->nr_pfns++; 
            }

            /* setup region_mfn[] for batch map.
             * For HVM guests, this interface takes PFNs, not MFNs */
            region_mfn[i] = hvm ? pfn : ctx->p2m[pfn]; 
        }
    }

    for ( i = 0, curpage = -1; i < j; i++ )
    {
        pfn      = pagebuf->pfn_types[i + curbatch] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
        pagetype = pagebuf->pfn_types[i + curbatch] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

        if ( pagetype == XEN_DOMCTL_PFINFO_XTAB )
            /* a bogus/unmapped page: skip it */
            continue;

        ++curpage;

        if ( pfn > dinfo->p2m_size )
        {
            ERROR("pfn out of range");
            goto err_mapped;
        }

        pfn_type[pfn] = pagetype;

        mfn = ctx->p2m[pfn];

        /* In verify mode, we use a copy; otherwise we work in place */
        //page = pagebuf->verify ? (void *)buf : (region_base + i*PAGE_SIZE);
	page = (unsigned long*)(pagebase + pfn * PAGE_SIZE);

        memcpy(page, pagebuf->pages + (curpage + curbatch) * PAGE_SIZE, PAGE_SIZE);

        pagetype &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

        if ( (pagetype >= XEN_DOMCTL_PFINFO_L1TAB) &&
             (pagetype <= XEN_DOMCTL_PFINFO_L4TAB) )
        {
            /*
            ** A page table page - need to 'uncanonicalize' it, i.e.
            ** replace all the references to pfns with the corresponding
            ** mfns for the new domain.
            **
            ** On PAE we need to ensure that PGDs are in MFNs < 4G, and
            ** so we may need to update the p2m after the main loop.
            ** Hence we defer canonicalization of L1s until then.
            */
            if ((ctx->pt_levels != 3) ||
                pae_extended_cr3 ||
                (pagetype != XEN_DOMCTL_PFINFO_L1TAB)) {

                if (!uncanonicalize_pagetable(xch, dom, ctx, page)) {
                    /*
                    ** Failing to uncanonicalize a page table can be ok
                    ** under live migration since the pages type may have
                    ** changed by now (and we'll get an update later).
                    */
                    DPRINTF("PT L%ld race on pfn=%08lx mfn=%08lx\n",
                            pagetype >> 28, pfn, mfn);
                    nraces++;
                    continue;
                }
            }
        }
        else if ( pagetype != XEN_DOMCTL_PFINFO_NOTAB )
        {
            ERROR("Bogus page type %lx page table is out of range: "
                  "i=%d p2m_size=%lu", pagetype, i, dinfo->p2m_size);
            goto err_mapped;
        }

        if ( pagebuf->verify )
        {
	    int res = memcmp(buf, (region_base + i*PAGE_SIZE), PAGE_SIZE);
            if ( res )
            {
                int v;

                DPRINTF("************** pfn=%lx type=%lx gotcs=%08lx "
                        "actualcs=%08lx\n", pfn, pagebuf->pfn_types[pfn],
                        csum_page(region_base + (i + curbatch)*PAGE_SIZE),
                        csum_page(buf));

                for ( v = 0; v < 4; v++ )
                {
                    unsigned long *p = (unsigned long *)
                        (region_base + i*PAGE_SIZE);
                    if ( buf[v] != p[v] )
                        DPRINTF("    %d: %08lx %08lx\n", v, buf[v], p[v]);
                }
            }
        }

        /*if ( !hvm &&
             xc_add_mmu_update(xch, mmu,
                               (((unsigned long long)mfn) << PAGE_SHIFT)
                               | MMU_MACHPHYS_UPDATE, pfn) )
        {
            PERROR("failed machpys update mfn=%lx pfn=%lx", mfn, pfn);
            goto err_mapped;
        }*/
    } /* end of 'batch' for loop */

    rc = nraces;

  err_mapped:

    return rc;
}

static void *map_frame_list_list(xc_interface *xch, uint32_t dom,
				struct domain_info_context *dinfo,
				shared_info_any_t *shinfo)
{
	int count = 100;
	void *p;
	uint64_t fll = GET_FIELD(shinfo, arch.pfn_to_mfn_frame_list_list);

	while ( count-- && (fll == 0) )
	{
		usleep(10000);
		fll = GET_FIELD(shinfo, arch.pfn_to_mfn_frame_list_list);
	}

	if ( fll == 0 )
	{
		ERROR("Time out waiting for frame list updated.");
		return NULL;
	}

	p = xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_READ, fll);
	if ( p == NULL )
		PERROR("Counldn't map p2m_frame_list_list (errno %d)", errno);
	
	return p;
}

static xen_pfn_t *map_p2m_table(xc_interface *xch,
				uint32_t dom,
				struct domain_info_context *dinfo,
				shared_info_any_t *live_shinfo)
{
	/* Double and single indirect references to the live P2M table */
	void *live_p2m_frame_list_list = NULL;
	void *live_p2m_frame_list = NULL;

	/* Copies of the above */
	xen_pfn_t *p2m_frame_list_list = NULL;
	xen_pfn_t *p2m_frame_list = NULL;

	/* The mapping of the live p2m table itself */
	xen_pfn_t *p2m = NULL;

	int i, success = 0;

	live_p2m_frame_list_list = map_frame_list_list(xch, dom, dinfo,
							 live_shinfo);

	if ( !live_p2m_frame_list_list)
		goto out;

	/* Get a local copy of the live_P2M_frame_list_list*/
	if ( !(p2m_frame_list_list = malloc(PAGE_SIZE)) )
	{
		PERROR("Counldn't allocate p2m_frame_list_list array");
		goto out;
	}
	memcpy(p2m_frame_list_list, live_p2m_frame_list_list, PAGE_SIZE);
	
	/* Canonicalize guest's unsigned long vs ours */
	if ( dinfo->guest_width > sizeof(unsigned long) )
		for ( i = 0; i < PAGE_SIZE/sizeof(unsigned long); i++)
			if ( i < PAGE_SIZE/dinfo->guest_width )
				p2m_frame_list_list[i] = ((uint64_t *)p2m_frame_list_list)[i];
			else
				p2m_frame_list_list[i] = 0;
	else if ( dinfo->guest_width < sizeof(unsigned long) )
		for ( i = PAGE_SIZE/sizeof(unsigned long) - 1; i >= 0; i-- )
			p2m_frame_list_list[i] = ((uint32_t *)p2m_frame_list_list)[i];

	live_p2m_frame_list = 
		xc_map_foreign_pages(xch, dom, PROT_READ | PROT_WRITE,
					p2m_frame_list_list,
					P2M_FLL_ENTRIES);
	if ( !live_p2m_frame_list )
	{
		PERROR("Counldn't map p2m_frame_list");
		goto out;
	}

	/* Get a local copy of the live_P2M_frame_list */
	if ( !(p2m_frame_list = malloc(P2M_TOOLS_FL_SIZE)) )
	{
		ERROR("counldn't allocate p2m_frame_list array");
		goto out;
	}
	memset(p2m_frame_list, 0, P2M_TOOLS_FL_SIZE);
	memcpy(p2m_frame_list, live_p2m_frame_list, P2M_GUEST_FL_SIZE);

	munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);
	live_p2m_frame_list = NULL;

	/* Canonicalize guest's unsigned long vs ours */
	if ( dinfo->guest_width > sizeof(unsigned long) )
		for ( i = 0; i < P2M_FL_ENTRIES; i++ )
			p2m_frame_list[i] = ((uint64_t *)p2m_frame_list)[i];
	else if ( dinfo->guest_width < sizeof(unsigned long) )
		for ( i = P2M_FL_ENTRIES - 1; i >= 0; i-- )
			p2m_frame_list[i] = ((uint32_t *)p2m_frame_list)[i];

	p2m = xc_map_foreign_pages(xch, dom, PROT_READ | PROT_WRITE,
					p2m_frame_list,
					P2M_FL_ENTRIES);
	if ( !p2m )
	{
		PERROR("Couldn't map p2m table");
		goto out;
	}

	success = 1;
	
out:
	if ( !success && p2m )
		munmap(p2m, P2M_FLL_ENTRIES * PAGE_SIZE);

	if ( live_p2m_frame_list_list )
		munmap(live_p2m_frame_list_list, PAGE_SIZE);
	
	if ( live_p2m_frame_list )
		munmap(live_p2m_frame_list, P2M_FLL_ENTRIES * PAGE_SIZE);

	if ( p2m_frame_list_list )
		free(p2m_frame_list_list);

	if ( p2m_frame_list )
		free(p2m_frame_list);

	return success ? p2m : NULL;
}

static int update_pfn_type(xc_interface *xch, uint32_t dom, int count, xen_pfn_t *pfn_batch,
			   xen_pfn_t *pfn_type_batch, xen_pfn_t *pfn_type)
{
    int k;

    if ( xc_get_pfn_type_batch(xch, dom, count, pfn_type_batch) )
    {
	ERROR("xc_get_pfn_type_batch for slaver failed");
	return -1;
    }

    for (k = 0; k < count; k++)
	pfn_type[pfn_batch[k]] = pfn_type_batch[k] & XEN_DOMCTL_PFINFO_LTAB_MASK;
    return 0;
}

int xc_domain_restore(xc_interface *xch, int io_fd, uint32_t dom,
                      unsigned int store_evtchn, unsigned long *store_mfn,
                      unsigned int console_evtchn, unsigned long *console_mfn,
                      unsigned int hvm, unsigned int pae, int superpages)
{
    DECLARE_DOMCTL;
    int rc = 1, frc, i, j, n, m;
    int pae_extended_cr3 = 0, ext_vcpucontext = 0;
    int vcpuextstate = 0;
    uint32_t vcpuextstate_size = 0;
    unsigned long mfn, pfn;
    unsigned int prev_pc;
    int nraces = 0;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;
    unsigned char shared_info_page[PAGE_SIZE]; /* saved contents from file */
    shared_info_any_t *old_shared_info = 
        (shared_info_any_t *)shared_info_page;
    shared_info_any_t *new_shared_info;

    /* A copy of the CPU context of the guest. */
    DECLARE_HYPERCALL_BUFFER(vcpu_guest_context_any_t, ctxt);

    /* A copy of the CPU eXtended States of the guest. */
    DECLARE_HYPERCALL_BUFFER(void, buffer);

    /* A table containing the type of each PFN (/not/ MFN!). */
    unsigned long *pfn_type = NULL;
    xen_pfn_t *pfn_type_slaver = NULL;
    int* pfn_err = NULL;

    xen_pfn_t *pfn_batch_slaver = NULL;
    xen_pfn_t *pfn_type_batch_slaver = NULL;

    /* A table of MFNs to map in the current region */
    xen_pfn_t *region_mfn = NULL;

    /* A copy of the pfn-to-mfn table frame list. */
    xen_pfn_t *p2m_frame_list = NULL;
    xen_pfn_t *p2m_frame_list_temp = NULL;
    
    /* A temporay mapping of the guest's p2m table(1 page) */
    xen_pfn_t *live_p2m = NULL;

    /* A copy of the pfn-to-mfn table(1 page) */
    xen_pfn_t *p2m = NULL;

    /* A temporary mapping of the guest's start_info page. */
    start_info_any_t *start_info;
    
    shared_info_any_t *live_shinfo = NULL;

    /* Our mapping of the current region (batch) */
    char *region_base;

    struct xc_mmu *mmu = NULL;

    struct mmuext_op pin[MAX_PIN_BATCH];
    unsigned int nr_pins;

    uint64_t vcpumap = 1ULL;
    unsigned int max_vcpu_id = 0;
    int new_ctxt_format = 0;

    pagebuf_t pagebuf;
    tailbuf_t tailbuf, tmptail;
    void* vcpup;
    uint64_t console_pfn = 0;

    int orig_io_fd_flags;

    static struct restore_ctx _ctx = {
        .live_p2m = NULL,
        .p2m = NULL,
    };
    static struct restore_ctx *ctx = &_ctx;
    struct domain_info_context *dinfo = &ctx->dinfo;
    FILE *fp;
    struct timeval time;
    unsigned long size = 0;
    char *pagebuff;
    unsigned long pagetype;
    char str[10];
    int remote_port = -1;
    int local_port = -1;
    xc_evtchn *xce;
    struct xs_handle *xsh;
    DECLARE_HYPERCALL;

    xc_shadow_op_stats_t stats;

    xc_dominfo_t info;
    unsigned long max_mem_pfn;

    fp = fopen("/root/yewei/1.txt", "at");
    fprintf(fp, "start.\n");
    fflush(fp);

    pagebuf_init(&pagebuf);
    memset(&tailbuf, 0, sizeof(tailbuf));
    tailbuf.ishvm = hvm;

    /* For info only */
    ctx->nr_pfns = 0;
    //ctx->completed = 1; // use timeout socket read
    ctx->completed = 0; // use timeout socket read

    // initilise fast suspend evtchn

    xce = xc_evtchn_open(NULL, 0);
    xsh = xs_daemon_open();
    if (xce == NULL || xsh == NULL) {
	fprintf(fp, "xc_evtchn_open error.\n");
	fflush(fp);
	//goto out;
    }

    if ( superpages )
        return 1;

    if ( xc_domain_getinfo(xch, dom, 1, &info) != 1 )
    {
        PERROR("Could not get domain info");
        return 1;
    }

    max_mem_pfn = info.max_memkb >> (PAGE_SHIFT - 10);

    ctxt = xc_hypercall_buffer_alloc(xch, ctxt, sizeof(*ctxt));

    if ( ctxt == NULL )
    {
        PERROR("Unable to allocate VCPU ctxt buffer");
        return 1;
    }


    if ( (orig_io_fd_flags = fcntl(io_fd, F_GETFL, 0)) < 0 ) {
        PERROR("unable to read IO FD flags");
        goto out;
    }

    /* Reserve the domid information in Hypervisor */    
    hypercall.op = __HYPERVISOR_which_side_op;
    hypercall.arg[0] = (unsigned long)dom;

    do_xen_hypercall(xch, &hypercall);

    syscall(NR_reset_suspend_count);
    	
    gettimeofday(&time, NULL);
    fprintf(fp, "[%d.%d]pre p2m point\n", (int)time.tv_sec, (int)time.tv_usec);
    fflush(fp);
    if ( RDEXACT(io_fd, &dinfo->p2m_size, sizeof(unsigned long)) )
    {
       	PERROR("read: p2m_size");
	goto out;
    }

    size = dinfo->p2m_size * PAGE_SIZE;
    pagebase = (char*)malloc(size);
    pfn_type = calloc(dinfo->p2m_size, sizeof(unsigned long));

    if (pagebase == NULL || pfn_type == NULL) {
	fprintf(fp, "cannot map pagebase or pfn_type\n");
	fflush(fp);
	goto out;
    }

    for (i = 0; i < dinfo->p2m_size; i++)
        pfn_type[i] = XEN_DOMCTL_PFINFO_XTAB;

    DPRINTF("xc_domain_restore start: p2m_size = %lx\n", dinfo->p2m_size);

    if ( !get_platform_info(xch, dom,
                        &ctx->max_mfn, &ctx->hvirt_start, &ctx->pt_levels, &dinfo->guest_width) )
    {
        ERROR("Unable to get platform info.");
        return 1;
    }
    
    /* The *current* word size of the guest isn't very interesting; for now
     * assume the guest will be the same as we are.  We'll fix that later
     * if we discover otherwise. */
    dinfo->guest_width = sizeof(unsigned long);
    ctx->pt_levels = (dinfo->guest_width == 8) ? 4 : (ctx->pt_levels == 2) ? 2 : 3; 
    
    if ( !hvm ) 
    {
        /* Load the p2m frame list, plus potential extended info chunk */
        p2m_frame_list = load_p2m_frame_list(xch, ctx,
            io_fd, &pae_extended_cr3, &ext_vcpucontext,
            &vcpuextstate, &vcpuextstate_size);

        if ( !p2m_frame_list )
            goto out;

    	if ( (p2m_frame_list_temp = malloc(P2M_TOOLS_FL_SIZE)) == NULL )
	   	goto out;

	if (first_time) {
       		/* Now that we know the word size, tell Xen about it */
        	memset(&domctl, 0, sizeof(domctl));
        	domctl.domain = dom;
        	domctl.cmd    = XEN_DOMCTL_set_address_size;
        	domctl.u.address_size.size = dinfo->guest_width * 8;
        	frc = do_domctl(xch, &domctl);
        	if ( frc != 0 )
       		{
            		PERROR("Unable to set guest address size.");
			gettimeofday(&time, NULL);
			fprintf(fp, "[%d.%d]Unable to set guest address size,ret=%d\n", (int)time.tv_sec, (int)time.tv_usec, frc);
			fflush(fp);
            		goto out;
        	}
    	}
    }

    /* We want zeroed memory so use calloc rather than malloc. */
    ctx->p2m   = calloc(dinfo->p2m_size, sizeof(xen_pfn_t));
    //pfn_type   = calloc(dinfo->p2m_size, sizeof(unsigned long));
    pfn_type_slaver   = calloc(dinfo->p2m_size, sizeof(xen_pfn_t));
    pfn_err = calloc(dinfo->p2m_size, sizeof(*pfn_err));
    pfn_batch_slaver = calloc(MAX_BATCH_SIZE, sizeof(xen_pfn_t));
    pfn_type_batch_slaver = calloc(MAX_BATCH_SIZE, sizeof(xen_pfn_t));

    if ( !pfn_batch_slaver || !pfn_type_batch_slaver)
    {
	ERROR("memory alloc pfn_batch_slaver or pfn_type_batch_slaver failed");
        errno = ENOMEM;
        goto out;
    }

    region_mfn = malloc(ROUNDUP(MAX_BATCH_SIZE * sizeof(xen_pfn_t), PAGE_SHIFT));
    ctx->p2m_batch = malloc(ROUNDUP(MAX_BATCH_SIZE * sizeof(xen_pfn_t), PAGE_SHIFT));

    if ( (ctx->p2m == NULL) || (pfn_type == NULL) ||
         (region_mfn == NULL) || (ctx->p2m_batch == NULL) )
    {
        ERROR("memory alloc failed");
        errno = ENOMEM;
        goto out;
    }

    memset(region_mfn, 0,
           ROUNDUP(MAX_BATCH_SIZE * sizeof(xen_pfn_t), PAGE_SHIFT)); 
    memset(ctx->p2m_batch, 0,
           ROUNDUP(MAX_BATCH_SIZE * sizeof(xen_pfn_t), PAGE_SHIFT)); 

    /* Get the domain's shared-info frame. */
    domctl.cmd = XEN_DOMCTL_getdomaininfo;
    domctl.domain = (domid_t)dom;
    if ( xc_domctl(xch, &domctl) < 0 )
    {
        PERROR("Could not get information on new domain");
        goto out;
    }
    shared_info_frame = domctl.u.getdomaininfo.shared_info_frame;

    if ( !hvm )
    {
	live_shinfo = xc_map_foreign_range(xch, dom, PAGE_SIZE,
						PROT_READ, shared_info_frame);
	if ( !live_shinfo )
	{
		PERROR("Counldn't map live_shinfo");
		goto out;
	}
    }

    if (!first_time) {
    	/* We should read the P2M table, because the VM once has run. */
	if ( !(ctx->live_p2m = map_p2m_table(xch, dom, dinfo, live_shinfo)) )
    	{
       		PERROR("Couldn't map p2m table");
       		fprintf(fp, "Couldn't map p2m table\n");
		fflush(fp);
       		goto out;
   	}
    	memcpy(ctx->p2m, ctx->live_p2m, dinfo->p2m_size * sizeof(xen_pfn_t));
    	munmap(ctx->live_p2m, P2M_FL_ENTRIES * PAGE_SIZE);
	
    }else {
   	 /* Mark all PFNs as invalid; we allocate on demand */
    	 for ( pfn = 0; pfn < dinfo->p2m_size; pfn++ )
		ctx->p2m[pfn] = INVALID_P2M_ENTRY;
    }

    if ( live_shinfo )
	munmap(live_shinfo, PAGE_SIZE);

    mmu = xc_alloc_mmu_updates(xch, dom);
    if ( mmu == NULL )
    {
       	PERROR("Could not initialise for MMU updates");
       	goto out;
    }

    xc_report_progress_start(xch, "Reloading memory pages", dinfo->p2m_size);

    /*
     * Now simply read each saved frame into its new machine frame.
     * We uncanonicalise page tables as we go.
     */
    prev_pc = 0;

    n = m = 0;

    to_send = xc_hypercall_buffer_alloc_pages(xch, to_send, NRPAGES(BITMAP_SIZE));
    if ( !to_send )
    {
	fprintf(fp, "Couldn't allocate to_send array");
	fflush(fp);
	goto out;
    }
    memset(to_send, 0xff, BITMAP_SIZE);

    
    if (ctx->completed)
	goto next_checkpoint; 		
 loadpages:
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]Loadpages\n", time.tv_sec, time.tv_usec);
    fflush(fp);
	
    for ( ; ; )
    {
        int j, curbatch;

        xc_report_progress_step(xch, n, dinfo->p2m_size);

        if ( !ctx->completed ) {
            pagebuf.nr_physpages = pagebuf.nr_pages = 0;
            if ( pagebuf_get_one(xch, ctx, &pagebuf, io_fd, dom) < 0 ) {
		gettimeofday(&time, NULL);
		fprintf(fp, "[%d.%d]Error when reading batch\n", (int)time.tv_sec, (int)time.tv_usec);
		fflush(fp);
                PERROR("Error when reading batch");
                goto out;
            }
        }
        j = pagebuf.nr_pages;

        DBGPRINTF("batch %d\n",j);

        if ( j == 0 ) {
            /* catch vcpu updates */
            if (pagebuf.new_ctxt_format) {
                vcpumap = pagebuf.vcpumap;
                max_vcpu_id = pagebuf.max_vcpu_id;
            }
            /* should this be deferred? does it change? */
            if ( pagebuf.identpt )
                xc_set_hvm_param(xch, dom, HVM_PARAM_IDENT_PT, pagebuf.identpt);
            if ( pagebuf.vm86_tss )
                xc_set_hvm_param(xch, dom, HVM_PARAM_VM86_TSS, pagebuf.vm86_tss);
            if ( pagebuf.console_pfn )
                console_pfn = pagebuf.console_pfn;
            break;  /* our work here is done */
        }

        /* break pagebuf into batches */
	//fprintf(fp, "applying pages.\n");
	fflush(fp);
        curbatch = 0;
        while ( curbatch < j ) {
            int brc;
            brc = apply_batch(xch, dom, ctx, region_mfn, pfn_type,
                              pae_extended_cr3, hvm, mmu, &pagebuf, curbatch);
            if ( brc < 0 ) {	
		gettimeofday(&time, NULL);
		fprintf(fp, "[%d.%d]error when apply_batch\n", (int)time.tv_sec, (int)time.tv_usec);
		fflush(fp);
                goto out;
	    }
            nraces += brc;

            curbatch += MAX_BATCH_SIZE;
        }

        pagebuf.nr_physpages = pagebuf.nr_pages = 0;

        n += j; /* crude stats */

        /* 
         * Discard cache for portion of file read so far up to last
         *  page boundary every 16MB or so.
         */
        m += j;
        if ( m > MAX_PAGECACHE_USAGE )
        {
            discard_file_cache(xch, io_fd, 0 /* no flush */);
            m = 0;
        }
    }
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]Exit from infinite for\n", time.tv_sec, time.tv_usec);
    fflush(fp);
    /*
     * Ensure we flush all machphys updates before potential PAE-specific
     * reallocations below.
     */
    //if ( !hvm && xc_flush_mmu_updates(xch, mmu) )
    //{
    //    PERROR("Error doing flush_mmu_updates()");
    //    goto out;
    //}

    // DPRINTF("Received all pages (%d races)\n", nraces);

    if ( !ctx->completed ) {

	gettimeofday(&time, NULL);
	fprintf(fp, "[%d.%d]!ctx->completed stands\n", (int)time.tv_sec, (int)time.tv_usec);
	fflush(fp);
        if ( buffer_tail(xch, ctx, &tailbuf, io_fd, max_vcpu_id, vcpumap,
                         ext_vcpucontext, vcpuextstate, vcpuextstate_size) < 0 ) {
            ERROR ("error buffering image tail");
            goto out;
        }

        ctx->completed = 1;

        /*
         * If more checkpoints are expected then shift into
         * nonblocking mode for the remainder.
         */
        if ( !ctx->last_checkpoint )
            fcntl(io_fd, F_SETFL, orig_io_fd_flags | O_NONBLOCK);
    }

    if (pagebuf.acpi_ioport_location == 1) {
        DBGPRINTF("Use new firmware ioport from the checkpoint\n");
        xc_set_hvm_param(xch, dom, HVM_PARAM_ACPI_IOPORTS_LOCATION, 1);
    } else if (pagebuf.acpi_ioport_location == 0) {
        DBGPRINTF("Use old firmware ioport from the checkpoint\n");
    } else {
        ERROR("Error, unknow acpi ioport location (%i)", pagebuf.acpi_ioport_location);
    }

    if ( ctx->last_checkpoint )
    {
        // DPRINTF("Last checkpoint, finishing\n");
	gettimeofday(&time, NULL);
	fprintf(fp, "[%lu.%06lu]Last checkpoint\n", time.tv_sec, time.tv_usec);
	fflush(fp);
	
        goto finish;
    }

    // DPRINTF("Buffered checkpoint\n");

next_checkpoint:

    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]begin pagebuf_get.\n", 
		time.tv_sec, time.tv_usec);

    if ( pagebuf_get(xch, ctx, &pagebuf, io_fd, dom) ) {
        PERROR("error when buffering batch, finishing");
	gettimeofday(&time, NULL);
	fprintf(fp, "[%d.%d]error when buffering batch\n", (int)time.tv_sec, (int)time.tv_usec);
	fflush(fp);
        goto finish;
    }
    
    vcpumap = pagebuf.vcpumap;
    max_vcpu_id = pagebuf.max_vcpu_id;
    
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]transmit %d pages, begin buffer_tail.\n",
		time.tv_sec, time.tv_usec, (int)pagebuf.nr_pages);
    
    memset(&tmptail, 0, sizeof(tmptail));
    tmptail.ishvm = hvm;
    if ( buffer_tail(xch, ctx, &tmptail, io_fd, max_vcpu_id, vcpumap,
                     ext_vcpucontext, vcpuextstate, vcpuextstate_size) < 0 ) {
        ERROR ("error buffering image tail, finishing");
	gettimeofday(&time, NULL);
	fprintf(fp, "[%d.%d]error buffering image tail\n", (int)time.tv_sec, (int)time.tv_usec);
	fflush(fp);
        goto finish;
    }
    tailbuf_free(&tailbuf);
    memcpy(&tailbuf, &tmptail, sizeof(tailbuf));
    
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]end buffer_tail.\n", 
		time.tv_sec, time.tv_usec);

    goto loadpages;

  finish:
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]Finish, ctx->pt_levels=%d, pae_extended_cr3=%d\n", 
		time.tv_sec, time.tv_usec, ctx->pt_levels, pae_extended_cr3);
    fflush(fp);
    
    if ( hvm )
        goto finish_hvm;

    if ( (ctx->pt_levels == 3) && !pae_extended_cr3 )
    {
        /*
        ** XXX SMH on PAE we need to ensure PGDs are in MFNs < 4G. This
        ** is a little awkward and involves (a) finding all such PGDs and
        ** replacing them with 'lowmem' versions; (b) upating the p2m[]
        ** with the new info; and (c) canonicalizing all the L1s using the
        ** (potentially updated) p2m[].
        **
        ** This is relatively slow (and currently involves two passes through
        ** the pfn_type[] array), but at least seems to be correct. May wish
        ** to consider more complex approaches to optimize this later.
        */

        int j, k;
      
        /* First pass: find all L3TABs current in > 4G mfns and get new mfns */
        for ( i = 0; i < dinfo->p2m_size; i++ )
        {
            if ( ((pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) ==
                  XEN_DOMCTL_PFINFO_L3TAB) &&
                 (ctx->p2m[i] > 0xfffffUL) )
            {
                unsigned long new_mfn;
                uint64_t l3ptes[4];
                uint64_t *l3tab;

                l3tab = (uint64_t *)
                    xc_map_foreign_range(xch, dom, PAGE_SIZE,
                                         PROT_READ, ctx->p2m[i]);

                for ( j = 0; j < 4; j++ )
                    l3ptes[j] = l3tab[j];

                munmap(l3tab, PAGE_SIZE);

                new_mfn = xc_make_page_below_4G(xch, dom, ctx->p2m[i]);
                if ( !new_mfn )
                {
                    PERROR("Couldn't get a page below 4GB :-(");
                    goto out;
                }

                ctx->p2m[i] = new_mfn;
                if ( xc_add_mmu_update(xch, mmu,
                                       (((unsigned long long)new_mfn)
                                        << PAGE_SHIFT) |
                                       MMU_MACHPHYS_UPDATE, i) )
                {
                    PERROR("Couldn't m2p on PAE root pgdir");
                    goto out;
                }

                l3tab = (uint64_t *)
                    xc_map_foreign_range(xch, dom, PAGE_SIZE,
                                         PROT_READ | PROT_WRITE, ctx->p2m[i]);

                for ( j = 0; j < 4; j++ )
                    l3tab[j] = l3ptes[j];

                munmap(l3tab, PAGE_SIZE);
            }
        }

        /* Second pass: find all L1TABs and uncanonicalize them */
        j = 0;

        for ( i = 0; i < dinfo->p2m_size; i++ )
        {
            if ( ((pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) ==
                  XEN_DOMCTL_PFINFO_L1TAB) )
            {
                region_mfn[j] = ctx->p2m[i];
                j++;
            }

            if ( (i == (dinfo->p2m_size-1)) || (j == MAX_BATCH_SIZE) )
            {
                region_base = xc_map_foreign_pages(
                    xch, dom, PROT_READ | PROT_WRITE, region_mfn, j);
                if ( region_base == NULL )
                {
                    PERROR("map batch failed");
                    goto out;
                }

                for ( k = 0; k < j; k++ )
                {
                    if ( !uncanonicalize_pagetable(
                        xch, dom, ctx,
                        region_base + k*PAGE_SIZE) )
                    {
                        ERROR("failed uncanonicalize pt!");
                        goto out;
                    }
                }

                munmap(region_base, j*PAGE_SIZE);
                j = 0;
            }
        }

        if ( xc_flush_mmu_updates(xch, mmu) )
        {
            PERROR("Error doing xc_flush_mmu_updates()");
            goto out;
        }
    }

    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]start step1\n", time.tv_sec, time.tv_usec);
    /* Step1: pin non-dirty L1 pagetables: ~to_send & mL1 (= ~to_send & sL1) */
    nr_pins = 0;
    for ( i = 0; i < dinfo->p2m_size; i++ )
    {
        switch ( pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            if (pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LPINTAB) // don't pin already pined
		continue;
	    if (test_bit(i, to_send)) // don't pin dirty
		continue;
	    // here, it must also be L1 in slaver, otherwise it is dirty.(add test code ?) */

            pin[nr_pins].cmd = MMUEXT_PIN_L1_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L4TAB:
        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = ctx->p2m[i];
        nr_pins++;
 
        /* Batch full? Then flush. */
        if ( nr_pins == MAX_PIN_BATCH )
        {
            if ( xc_mmuext_op(xch, pin, nr_pins, dom) < 0 )
            {
                PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
                goto out;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ( (nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0) )
    {
        PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
        goto out;
    }

    /* Step2: unpin pagetables execpt non-dirty L1: sL2 + sL3 + sL4 + (to_send & sL1) */
    nr_pins = 0;
    for ( i = 0; i < dinfo->p2m_size; i++ )
    {
        if ( (pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LPINTAB) == 0 ) {
	    //pagetype = pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK;
	    //if (pagetype >= XEN_DOMCTL_PFINFO_L1TAB && pagetype <= XEN_DOMCTL_PFINFO_L4TAB)
	    //	fprintf(fp, "pfn = %d, page table but not pinned.\n", i);
            continue;
	}

        switch ( pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
	    if (!test_bit(i, to_send)) // it is in (~to_send & mL1), keep it
		continue;
	    // fallthrough
        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L4TAB:
            pin[nr_pins].cmd = MMUEXT_UNPIN_TABLE;
            break;

        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = ctx->p2m[i];
        nr_pins++;
 
        /* Batch full? Then flush. */
        if ( nr_pins == MAX_PIN_BATCH )
        {
            if ( xc_mmuext_op(xch, pin, nr_pins, dom) < 0 )
            {
                PERROR("Failed to unpin batch of %d page tables", nr_pins);
                goto out;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ( (nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0) )
    {
        PERROR("Failed to unpin batch of %d page tables", nr_pins);
        goto out;
    }

    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]finish step2 \n", time.tv_sec, time.tv_usec);

    /* Step 3: copy dirty page */
    //for (pfn = 0; pfn < dinfo->p2m_size; pfn++ ) {
if (1){
    long dirty_all = 0, dirty_l4 = 0, dirty_l3 = 3, dirty_l2 = 0, dirty_l1 = 0;

    for (j = pfn = 0; pfn < max_mem_pfn; pfn++) {
	if ( !test_bit(pfn, to_send) )
		continue;
	
	dirty_all++;
	pagetype = pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTAB_MASK;
		
	if (pagetype == XEN_DOMCTL_PFINFO_XTAB)
		// a bogus/unmapped page: skip it
		continue;

        switch ( pagetype )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
		dirty_l1++;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
		dirty_l2++;
            break;

        case XEN_DOMCTL_PFINFO_L3TAB:
		dirty_l3++;
            break;

        case XEN_DOMCTL_PFINFO_L4TAB:
		dirty_l4++;
            break;

        default:
            break;
        }

	mfn = ctx->p2m[pfn];
	j++;
	if (0) { /* mfncopy_op */
		pagebuff = (char *)(pagebase + pfn * PAGE_SIZE);

		//continue;
		hypercall.op = __HYPERVISOR_mfncopy_op;
		hypercall.arg[0] = (unsigned long)mfn;
		hypercall.arg[1] = (unsigned long)pagebuff;

		do_xen_hypercall(xch, &hypercall);
	} else { /* foreign mmap */
		int pfn_err = 0;
		char *region_base_slaver;
		xen_pfn_t region_mfn_slaver = mfn;

		region_base_slaver = xc_map_foreign_bulk(xch, dom,
			PROT_WRITE, &region_mfn_slaver, &pfn_err, 1);

		if (!region_base_slaver || pfn_err) {
			ERROR("laijs xc_map_foreign_bulk failed");
			return -1;
		}

		pagebuff = (char *)(pagebase + pfn * PAGE_SIZE);
		memcpy(region_base_slaver, pagebuff, PAGE_SIZE);
		munmap(region_base_slaver, PAGE_SIZE);
	}

	if ( !hvm &&
		xc_add_mmu_update(xch, mmu,
				(((unsigned long long)mfn) << PAGE_SHIFT)
				| MMU_MACHPHYS_UPDATE, pfn) )
	{
		fprintf(fp, "coping back memory error!\n");
		fflush(fp);
		goto out;
	}
    }
    /*
     * Ensure we flush all machphys updates before potential PAE-specific
     * reallocations below.
     */
    if ( !hvm && xc_flush_mmu_updates(xch, mmu) )
    {
        PERROR("Error doing flush_mmu_updates()");
        goto out;
    }
	fprintf(fp,	"dirty_all=%ld\n"
			"dirty_all_pt=%ld\n"
			"dirty_l4=%ld\n"
			"dirty_l3=%ld\n"
			"dirty_l2=%ld\n"
			"dirty_l1=%ld\n",
			dirty_all,
			dirty_l4 + dirty_l3 + dirty_l2 + dirty_l1,
			dirty_l4,
			dirty_l3,
			dirty_l2,
			dirty_l1);
	fflush(fp);
}

    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]start step4\n", time.tv_sec, time.tv_usec);

    /* Step 4: pin master pt */
    /*
     * Pin page tables. Do this after writing to them as otherwise Xen
     * will barf when doing the type-checking.
     */

    nr_pins = 0;
    for ( i = 0; i < dinfo->p2m_size; i++ )
    {
        if ( (pfn_type[i] & XEN_DOMCTL_PFINFO_LPINTAB) == 0 ) {
	    //pagetype = pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK;
	    //if (pagetype >= XEN_DOMCTL_PFINFO_L1TAB && pagetype <= XEN_DOMCTL_PFINFO_L4TAB)
	    //	fprintf(fp, "pfn = %d, page table but not pinned.\n", i);
            continue;
	}

        switch ( pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
	    if (!test_bit(i, to_send)) // it is in (~to_send & mL1)(=~to_send & sL1), already pined
		continue;
            pin[nr_pins].cmd = MMUEXT_PIN_L1_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L2_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L3TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L3_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L4TAB:
            pin[nr_pins].cmd = MMUEXT_PIN_L4_TABLE;
            break;

        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = ctx->p2m[i];
        nr_pins++;
 
        /* Batch full? Then flush. */
        if ( nr_pins == MAX_PIN_BATCH )
        {
            if ( xc_mmuext_op(xch, pin, nr_pins, dom) < 0 )
            {
                PERROR("Failed to pin batch of %d page tables", nr_pins);
                goto out;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ( (nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0) )
    {
        PERROR("Failed to pin batch of %d page tables", nr_pins);
        goto out;
    }

    /* Step5: unpin unneeded non-dirty L1 pagetables: ~to_send & mL1 (= ~to_send & sL1) */
    nr_pins = 0;
    for ( i = 0; i < dinfo->p2m_size; i++ )
    {
        switch ( pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            if (pfn_type[i] & XEN_DOMCTL_PFINFO_LPINTAB) // still needed
		continue;
	    if (test_bit(i, to_send)) // not pined by step 1
		continue;

            pin[nr_pins].cmd = MMUEXT_UNPIN_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L4TAB:
        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = ctx->p2m[i];
        nr_pins++;
 
        /* Batch full? Then flush. */
        if ( nr_pins == MAX_PIN_BATCH )
        {
            if ( xc_mmuext_op(xch, pin, nr_pins, dom) < 0 )
            {
                PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
                goto out;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ( (nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0) )
    {
        PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
        goto out;
    }
    /* end Step 5 */
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]finish step5\n", time.tv_sec, time.tv_usec);

    /*
     * copy memory from shared buffer into VM
     */
    memcpy(pfn_type_slaver, pfn_type, dinfo->p2m_size * sizeof(xen_pfn_t));
    
    DPRINTF("Memory reloaded (%ld pages)\n", ctx->nr_pfns);

    /* Get the list of PFNs that are not in the psuedo-phys map */
    {
        int nr_frees = 0;

        for ( i = 0; i < tailbuf.u.pv.pfncount; i++ )
        {
            unsigned long pfn = tailbuf.u.pv.pfntab[i];

            if ( ctx->p2m[pfn] != INVALID_P2M_ENTRY )
            {
                /* pfn is not in physmap now, but was at some point during
                   the save/migration process - need to free it */
                tailbuf.u.pv.pfntab[nr_frees++] = ctx->p2m[pfn];
                ctx->p2m[pfn]  = INVALID_P2M_ENTRY; /* not in pseudo-physical map */
            }
        }

        if ( nr_frees > 0 )
        {
            if ( (frc = xc_domain_decrease_reservation(xch, dom, nr_frees, 0, tailbuf.u.pv.pfntab)) != nr_frees )
            {
                PERROR("Could not decrease reservation : %d", frc);
                goto out;
            }
            else
                DPRINTF("Decreased reservation by %d pages\n", tailbuf.u.pv.pfncount);
        }
    }

    fprintf(fp, "vcpu state start...\n");
    fflush(fp);

    vcpup = tailbuf.u.pv.vcpubuf;
    for ( i = 0; i <= max_vcpu_id; i++ )
    {
        if ( !(vcpumap & (1ULL << i)) )
            continue;

        memcpy(ctxt, vcpup, ((dinfo->guest_width == 8) ? sizeof(ctxt->x64)
                              : sizeof(ctxt->x32)));
        vcpup += (dinfo->guest_width == 8) ? sizeof(ctxt->x64) : sizeof(ctxt->x32);

        DPRINTF("read VCPU %d\n", i);
	fprintf(fp, "read VCPU %d\n", i);

        if ( !new_ctxt_format )
            SET_FIELD(ctxt, flags, GET_FIELD(ctxt, flags) | VGCF_online);

        if ( i == 0 )
        {
            /*
             * Uncanonicalise the suspend-record frame number and poke
             * resume record.
             */
            pfn = GET_FIELD(ctxt, user_regs.edx);
            if ( (pfn >= dinfo->p2m_size) ||
                 (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB) )
            {
                ERROR("Suspend record frame number is bad");
                goto out;
            }
            mfn = ctx->p2m[pfn];
            SET_FIELD(ctxt, user_regs.edx, mfn);
            start_info = xc_map_foreign_range(
                xch, dom, PAGE_SIZE, PROT_READ | PROT_WRITE, mfn);
            SET_FIELD(start_info, nr_pages, dinfo->p2m_size);
            SET_FIELD(start_info, shared_info, shared_info_frame<<PAGE_SHIFT);
            SET_FIELD(start_info, flags, 0);
            *store_mfn = ctx->p2m[GET_FIELD(start_info, store_mfn)];
            SET_FIELD(start_info, store_mfn, *store_mfn);
            SET_FIELD(start_info, store_evtchn, store_evtchn);
            *console_mfn = ctx->p2m[GET_FIELD(start_info, console.domU.mfn)];
            SET_FIELD(start_info, console.domU.mfn, *console_mfn);
            SET_FIELD(start_info, console.domU.evtchn, console_evtchn);
            munmap(start_info, PAGE_SIZE);
        }
        /* Uncanonicalise each GDT frame number. */
        if ( GET_FIELD(ctxt, gdt_ents) > 8192 )
        {
            ERROR("GDT entry count out of range");
            goto out;
        }

        for ( j = 0; (512*j) < GET_FIELD(ctxt, gdt_ents); j++ )
        {
            pfn = GET_FIELD(ctxt, gdt_frames[j]);
            if ( (pfn >= dinfo->p2m_size) ||
                 (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB) )
            {
                ERROR("GDT frame number %i (0x%lx) is bad", 
                      j, (unsigned long)pfn);
                goto out;
            }
            SET_FIELD(ctxt, gdt_frames[j], ctx->p2m[pfn]);
        }
        /* Uncanonicalise the page table base pointer. */
        pfn = UNFOLD_CR3(GET_FIELD(ctxt, ctrlreg[3]));

        if ( pfn >= dinfo->p2m_size )
        {
            ERROR("PT base is bad: pfn=%lu p2m_size=%lu type=%08lx",
                  pfn, dinfo->p2m_size, pfn_type[pfn]);
            goto out;
        }

        if ( (pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) !=
             ((unsigned long)ctx->pt_levels<<XEN_DOMCTL_PFINFO_LTAB_SHIFT) )
        {
            ERROR("PT base is bad. pfn=%lu nr=%lu type=%08lx %08lx",
                  pfn, dinfo->p2m_size, pfn_type[pfn],
                  (unsigned long)ctx->pt_levels<<XEN_DOMCTL_PFINFO_LTAB_SHIFT);
            goto out;
        }
        SET_FIELD(ctxt, ctrlreg[3], FOLD_CR3(ctx->p2m[pfn]));

        /* Guest pagetable (x86/64) stored in otherwise-unused CR1. */
        if ( (ctx->pt_levels == 4) && (ctxt->x64.ctrlreg[1] & 1) )
        {
            pfn = UNFOLD_CR3(ctxt->x64.ctrlreg[1] & ~1);
            if ( pfn >= dinfo->p2m_size )
            {
                ERROR("User PT base is bad: pfn=%lu p2m_size=%lu",
                      pfn, dinfo->p2m_size);
                goto out;
            }
            if ( (pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK) !=
                 ((unsigned long)ctx->pt_levels<<XEN_DOMCTL_PFINFO_LTAB_SHIFT) )
            {
                ERROR("User PT base is bad. pfn=%lu nr=%lu type=%08lx %08lx",
                      pfn, dinfo->p2m_size, pfn_type[pfn],
                      (unsigned long)ctx->pt_levels<<XEN_DOMCTL_PFINFO_LTAB_SHIFT);
                goto out;
            }
            ctxt->x64.ctrlreg[1] = FOLD_CR3(ctx->p2m[pfn]);
        }
        domctl.cmd = XEN_DOMCTL_setvcpucontext;
        domctl.domain = (domid_t)dom;
        domctl.u.vcpucontext.vcpu = i;
        set_xen_guest_handle(domctl.u.vcpucontext.ctxt, ctxt);
        frc = xc_domctl(xch, &domctl);
        if ( frc != 0 )
        {
            PERROR("Couldn't build vcpu%d", i);
            goto out;
        }

        if ( !ext_vcpucontext )
            goto vcpu_ext_state_restore;
        memcpy(&domctl.u.ext_vcpucontext, vcpup, 128);
        vcpup += 128;
        domctl.cmd = XEN_DOMCTL_set_ext_vcpucontext;
        domctl.domain = dom;
        frc = xc_domctl(xch, &domctl);
        if ( frc != 0 )
        {
            PERROR("Couldn't set extended vcpu%d info", i);
            goto out;
        }

 vcpu_ext_state_restore:
        if ( !vcpuextstate )
            continue;

        memcpy(&domctl.u.vcpuextstate.xfeature_mask, vcpup,
               sizeof(domctl.u.vcpuextstate.xfeature_mask));
        vcpup += sizeof(domctl.u.vcpuextstate.xfeature_mask);
        memcpy(&domctl.u.vcpuextstate.size, vcpup,
               sizeof(domctl.u.vcpuextstate.size));
        vcpup += sizeof(domctl.u.vcpuextstate.size);

        buffer = xc_hypercall_buffer_alloc(xch, buffer,
                                           domctl.u.vcpuextstate.size);
        if ( !buffer )
        {
            PERROR("Could not allocate buffer to restore eXtended States");
            goto out;
        }
        memcpy(buffer, vcpup, domctl.u.vcpuextstate.size);
        vcpup += domctl.u.vcpuextstate.size;

        domctl.cmd = XEN_DOMCTL_setvcpuextstate;
        domctl.domain = dom;
        domctl.u.vcpuextstate.vcpu = i;
        set_xen_guest_handle(domctl.u.vcpuextstate.buffer, buffer);
        frc = xc_domctl(xch, &domctl);
        if ( frc != 0 )
        {
            PERROR("Couldn't set eXtended States for vcpu%d", i);
            goto out;
        }
        xc_hypercall_buffer_free(xch, buffer);
    }

    memcpy(shared_info_page, tailbuf.u.pv.shared_info_page, PAGE_SIZE);

    DPRINTF("Completed checkpoint load\n");

    /* Restore contents of shared-info page. No checking needed. */
    new_shared_info = xc_map_foreign_range(
        xch, dom, PAGE_SIZE, PROT_WRITE, shared_info_frame);

    /* restore saved vcpu_info and arch specific info */
    MEMCPY_FIELD(new_shared_info, old_shared_info, vcpu_info);
    MEMCPY_FIELD(new_shared_info, old_shared_info, arch);

    /* clear any pending events and the selector */
    MEMSET_ARRAY_FIELD(new_shared_info, evtchn_pending, 0);
    for ( i = 0; i < XEN_LEGACY_MAX_VCPUS; i++ )
	    SET_FIELD(new_shared_info, vcpu_info[i].evtchn_pending_sel, 0);

    /* mask event channels */
    MEMSET_ARRAY_FIELD(new_shared_info, evtchn_mask, 0xff);

    /* leave wallclock time. set by hypervisor */
    munmap(new_shared_info, PAGE_SIZE);

    /* Uncanonicalise the pfn-to-mfn table frame-number list. */
    //fprintf(fp, "P2M_FL_ENTRIES=%lu, dinfo->p2m_size=%lu:\n", P2M_FL_ENTRIES, dinfo->p2m_size);
    j = 0;
    for ( i = 0; i < P2M_FL_ENTRIES; i++ )
    {
        pfn = p2m_frame_list[i];
	//fprintf(fp, "%ld ", pfn);
        if ( (pfn >= dinfo->p2m_size) || (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB) )
        {
            ERROR("PFN-to-MFN frame number %i (%#lx) is bad", i, pfn);
            goto out;
        }

        if (!test_bit(pfn, to_send))
            continue;

        p2m_frame_list_temp[j++] = ctx->p2m[pfn];
    }

    if (j)
    {
        /* Copy the P2M we've constructed to the 'live' P2M */
        if ( !(ctx->live_p2m = xc_map_foreign_pages(xch, dom, PROT_WRITE,
                                                    p2m_frame_list_temp, j)) )
        {
            PERROR("Couldn't map p2m table");
            goto out;
        }

        j = 0;
        for ( i = 0; i < P2M_FL_ENTRIES; i++ )
        {
            pfn = p2m_frame_list[i];
            if (!test_bit(pfn, to_send))
                continue;

            live_p2m = (xen_pfn_t *)((char *)ctx->live_p2m + PAGE_SIZE * j++);
            /* If the domain we're restoring has a different word size to ours,
             * we need to adjust the live_p2m assignment appropriately */
            if ( dinfo->guest_width > sizeof (xen_pfn_t) )
            {
                n = (i + 1) * FPP - 1;
                for ( i = FPP - 1; i >= 0; i-- )
                    ((uint64_t *)live_p2m)[i] = (long)ctx->p2m[n--];
            }
            else if ( dinfo->guest_width < sizeof (xen_pfn_t) )
            {
                n = i * FPP;
                for ( i = 0; i < FPP; i++ )
                    ((uint32_t *)live_p2m)[i] = ctx->p2m[n++];
            }
            else
            {
                p2m = (xen_pfn_t *)((char *)ctx->p2m + PAGE_SIZE * i);
                memcpy(live_p2m, p2m, PAGE_SIZE);
            }
        }
        munmap(ctx->live_p2m, j * PAGE_SIZE);
    }

    DPRINTF("Domain ready to be built.\n");

    rc = 0;

    // output the store-mfn & console-mfn	 	
    printf("store-mfn %li\n", *store_mfn);
    printf("console-mfn %li\n", *console_mfn);
    	
	/* Enable dirty-log */
  	if ( xc_shadow_control(xch, dom,
			XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
			NULL, 0, NULL, 0, NULL) < 0 )
    	{
		frc = xc_shadow_control(xch, dom, XEN_DOMCTL_SHADOW_OP_OFF,
			NULL, 0, NULL, 0, NULL);
		if ( frc >= 0 )
		{
			frc = xc_shadow_control(xch, dom,
					XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
					NULL, 0, NULL, 0, NULL);
		}
		if ( frc < 0 )
		{
			fprintf(fp, "Couldn't enable shadow mode (rc %d) (err %s)\n", frc, strerror(errno) );
			fflush(fp);
			goto out;
		}
	}
    // notify python code checkpoint finish
    printf("finish\n");
    fflush(stdout);
    
    // wait domain resume, then connect the suspend evtchn
    scanf("%s", str);
    while (1) {
    	frc = syscall(NR_wait_resume);
	if (frc == 0)break;
    }

    if (first_time) {
	sleep(10);
    	remote_port = xs_suspend_evtchn_port(dom);
    	if (remote_port < 0) {
		fprintf(fp, "get evtchn port error.\n");
		fflush(fp);
    	}

	fprintf(fp, "dom=%d, remote_port=%d.\n", dom, remote_port);

    	local_port = xc_suspend_evtchn_init(xch, xce, dom, remote_port);
   	 if (local_port < 0) {
		fprintf(fp, "evtchn init error.\n");
		fflush(fp);
   	 }
    }

    printf("resume\n");
    fflush(stdout);

    fprintf(fp, "waiting for suspend...\n");
    fflush(fp);
    scanf("%s", str);
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]read suspend?=%s.\n", 
		time.tv_sec, time.tv_usec, str);
    fflush(fp);

    if ( strcmp(str, "suspend") ) goto out;
    //if ( !strcmp(str, "EOF") )goto out;
    //if ( !strcmp(str, "exception") )goto out;
   
    // notify the suspend evtchn
    frc = xc_evtchn_notify(xce, local_port);
    if (frc < 0) {
	fprintf(fp, "failed to notify suspend request channel.\n");
	fflush(fp);
    }

    fprintf(fp, "waiting suspend done.\n");
    fflush(fp);
    frc = xc_await_suspend(xch, xce, local_port);
    if (frc < 0) {
	fprintf(fp, "suspend failed");
	fflush(fp);
    }

    printf("suspend\n");
    fflush(stdout); 

    fprintf(fp, "waiting for start...\n");
    fflush(fp);
    scanf("%s", str);
	
    fprintf(fp, "receive1: %s\n", str);
    fflush(fp);

    if ( !strcmp(str, "EOF") )goto out;
    if ( !strcmp(str, "exception") )goto out;
    // start
    scanf("%s", str);
    fprintf(fp, "receive2: %s\n", str);
    fflush(fp);
    store_evtchn = atoi(str);
    scanf("%s", str);
    fprintf(fp, "receive3: %s\n", str);
    fflush(fp);
    console_evtchn = atoi(str);

    // get dirty pages
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]begin get dirty-log.\n", 
		time.tv_sec, time.tv_usec);
    memset(to_send, 0x0, BITMAP_SIZE);
    if ( xc_shadow_control(xch, dom,
			XEN_DOMCTL_SHADOW_OP_CLEAN, HYPERCALL_BUFFER(to_send),
			dinfo->p2m_size, NULL, 0, &stats) != dinfo->p2m_size )
    {
	fprintf(fp, "Error flushing shadow PT\n");
	fflush(fp);
	goto out;
    }
    for (i = j = 0; i < max_mem_pfn; i++) {
	if ( !test_bit(i, to_send) )
		continue;
	j++;
    }
	
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]end get dirty-log.\n", 
		time.tv_sec, time.tv_usec);
    fprintf(fp, "local dirty page=%d.\n", j);
    /*fprintf(fp, "dirty pages:\n");
    for (pfn = 0; pfn < 65536; pfn++) {
	if ( test_bit(pfn, to_send ) )
		fprintf(fp, "%ld ", pfn);
    }
    fprintf(fp, "\n");*/
    if ( xc_shadow_control(xch, dom,
			XEN_DOMCTL_SHADOW_OP_OFF,
			NULL, 0, NULL, 0, NULL) < 0 )
    {
	fprintf(fp, "Warning - couldn't disable shadow mode\n");
	fflush(fp);
	goto out;
    }
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]end off dirty-log.\n", 
		time.tv_sec, time.tv_usec);
    j = 0;
    for (i = 0; i < max_mem_pfn; i++) {
	if ( !test_bit(i, to_send) )
		continue;
        pfn_batch_slaver[j] = i;
	pfn_type_batch_slaver[j++] = ctx->p2m[i];
	if (j == MAX_BATCH_SIZE)
	{
	    if (update_pfn_type(xch, dom, j, pfn_batch_slaver, pfn_type_batch_slaver, pfn_type_slaver))
		goto out;
	    j = 0;
	}
    }

    if (j)
    {
	if (update_pfn_type(xch, dom, j, pfn_batch_slaver, pfn_type_batch_slaver, pfn_type_slaver))
	    goto out;
    }
	
    // reset memory
    hypercall.op = __HYPERVISOR_reset_memory_op;
    hypercall.arg[0] = (unsigned long)dom;

    do_xen_hypercall(xch, &hypercall);
    
    gettimeofday(&time, NULL);
    fprintf(fp, "[%lu.%06lu]end reset memory.\n", 
		time.tv_sec, time.tv_usec);
    
    //goto loadpages;
    first_time = 0;
    goto next_checkpoint;

    //goto out;
    // ctx->completed = 0;
    //goto next_checkpoint;

  finish_hvm:
    /* Dump the QEMU state to a state file for QEMU to load */
    if ( dump_qemu(xch, dom, &tailbuf.u.hvm) ) {
        PERROR("Error dumping QEMU state to file");
        goto out;
    }

    /* These comms pages need to be zeroed at the start of day */
    if ( xc_clear_domain_page(xch, dom, tailbuf.u.hvm.magicpfns[0]) ||
         xc_clear_domain_page(xch, dom, tailbuf.u.hvm.magicpfns[1]) ||
         xc_clear_domain_page(xch, dom, tailbuf.u.hvm.magicpfns[2]) )
    {
        PERROR("error zeroing magic pages");
        goto out;
    }

    if ( (frc = xc_set_hvm_param(xch, dom,
                                 HVM_PARAM_IOREQ_PFN, tailbuf.u.hvm.magicpfns[0]))
         || (frc = xc_set_hvm_param(xch, dom,
                                    HVM_PARAM_BUFIOREQ_PFN, tailbuf.u.hvm.magicpfns[1]))
         || (frc = xc_set_hvm_param(xch, dom,
                                    HVM_PARAM_STORE_PFN, tailbuf.u.hvm.magicpfns[2]))
         || (frc = xc_set_hvm_param(xch, dom,
                                    HVM_PARAM_PAE_ENABLED, pae))
         || (frc = xc_set_hvm_param(xch, dom,
                                    HVM_PARAM_STORE_EVTCHN,
                                    store_evtchn)) )
    {
        PERROR("error setting HVM params: %i", frc);
        goto out;
    }
    *store_mfn = tailbuf.u.hvm.magicpfns[2];

    if ( console_pfn ) {
        if ( xc_clear_domain_page(xch, dom, console_pfn) ) {
            PERROR("error zeroing console page");
            goto out;
        }
        if ( (frc = xc_set_hvm_param(xch, dom, 
                                    HVM_PARAM_CONSOLE_PFN, console_pfn)) ) {
            PERROR("error setting HVM param: %i", frc);
            goto out;
        }
        *console_mfn = console_pfn;
    }

    frc = xc_domain_hvm_setcontext(xch, dom, tailbuf.u.hvm.hvmbuf,
                                   tailbuf.u.hvm.reclen);
    if ( frc )
    {
        PERROR("error setting the HVM context");
        goto out;
    }

    /* HVM success! */
    rc = 0;

 out:
    gettimeofday(&time, NULL);
    fprintf(fp, "[%d.%d]Out\n", (int)time.tv_sec, (int)time.tv_usec);
    fflush(fp);
    fclose(fp);
    xc_evtchn_close(xce);
    xs_daemon_close(xsh);

    xc_hypercall_buffer_free(xch, ctxt);
    free(mmu);
    free(ctx->p2m);
    //free(pfn_type);
    free(pfn_err);
    tailbuf_free(&tailbuf);

    free(pfn_type);
    free(pagebase);
    /* discard cache for save file  */
    discard_file_cache(xch, io_fd, 1 /*flush*/);

    fcntl(io_fd, F_SETFL, orig_io_fd_flags);

    DPRINTF("Restore exit with rc=%d\n", rc);

    return rc;
}
/*
 * Local variables:
 * mode: C
 * c-set-style: "BSD"
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 */
