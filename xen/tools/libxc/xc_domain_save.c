/******************************************************************************
 * xc_linux_save.c
 *
 * Save the state of a running Linux session.
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
 * Copyright (c) 2003, K A Fraser.
 */

#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <unistd.h>
#include <syscall.h>
#include <sys/time.h>
#include <stdio.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <asm/ioctl.h>

#include "xc_private.h"
#include "xc_dom.h"
#include "xg_private.h"
#include "xg_save_restore.h"

#include <xen/hvm/params.h>
#include "xc_e820.h"

#define COMP_IOC_MAGIC		'k'
#define COMP_IOCTWAIT		_IO(COMP_IOC_MAGIC, 0)
#define COMP_IOCTSUSPEND	_IO(COMP_IOC_MAGIC, 1)
#define COMP_IOCTRESUME		_IO(COMP_IOC_MAGIC, 2)
#define COMP_IOCT_SWITCH    _IO(COMP_IOC_MAGIC, 3)
#define NR_wait_resume		312
#define NR_vif_block		313
#define NR_reset_suspend_count	314

static int curr_mode = COMPARE_MODE;
static uint64_t interval_us;
static int dev_fd = -1;

/*
** Default values for important tuning parameters. Can override by passing
** non-zero replacement values to xc_domain_save().
**
** XXX SMH: should consider if want to be able to override MAX_MBIT_RATE too.
**
*/
#define DEF_MAX_ITERS   29   /* limit us to 30 times round loop   */
#define DEF_MAX_FACTOR   3   /* never send more than 3x p2m_size  */
#define FAILOVER
#define NET_FW

struct save_ctx {
    unsigned long hvirt_start; /* virtual starting address of the hypervisor */
    unsigned int pt_levels; /* #levels of page tables used by the current guest */
    unsigned long max_mfn; /* max mfn of the whole machine */
    xen_pfn_t *live_p2m; /* Live mapping of the table mapping each PFN to its current MFN. */
    xen_pfn_t *live_m2p; /* Live mapping of system MFN to PFN table. */
    unsigned long m2p_mfn0;
    struct domain_info_context dinfo;
};

/* buffer for output */
struct outbuf {
    void* buf;
    size_t size;
    size_t pos;
};

#define OUTBUF_SIZE (16384 * 1024)

/* grep fodder: machine_to_phys */

#define mfn_to_pfn(_mfn)  (ctx->live_m2p[(_mfn)])

#define pfn_to_mfn(_pfn)                                            \
  ((xen_pfn_t) ((dinfo->guest_width==8)                               \
                ? (((uint64_t *)ctx->live_p2m)[(_pfn)])                  \
                : ((((uint32_t *)ctx->live_p2m)[(_pfn)]) == 0xffffffffU  \
                   ? (-1UL) : (((uint32_t *)ctx->live_p2m)[(_pfn)]))))

/*
 * Returns TRUE if the given machine frame number has a unique mapping
 * in the guest's pseudophysical map.
 */
#define MFN_IS_IN_PSEUDOPHYS_MAP(_mfn)          \
    (((_mfn) < (ctx->max_mfn)) &&                \
     ((mfn_to_pfn(_mfn) < (dinfo->p2m_size)) &&   \
      (pfn_to_mfn(mfn_to_pfn(_mfn)) == (_mfn))))

/*
** During (live) save/migrate, we maintain a number of bitmaps to track
** which pages we have to send, to fixup, and to skip.
*/

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

/* Returns the hamming weight (i.e. the number of bits set) in a N-bit word */
static inline unsigned int hweight32(unsigned int w)
{
    unsigned int res = (w & 0x55555555) + ((w >> 1) & 0x55555555);
    res = (res & 0x33333333) + ((res >> 2) & 0x33333333);
    res = (res & 0x0F0F0F0F) + ((res >> 4) & 0x0F0F0F0F);
    res = (res & 0x00FF00FF) + ((res >> 8) & 0x00FF00FF);
    return (res & 0x0000FFFF) + ((res >> 16) & 0x0000FFFF);
}

static inline int count_bits ( int nr, volatile void *addr)
{
    int i, count = 0;
    volatile unsigned long *p = (volatile unsigned long *)addr;
    /* We know that the array is padded to unsigned long. */
    for ( i = 0; i < (nr / (sizeof(unsigned long)*8)); i++, p++ )
        count += hweight32(*p);
    return count;
}

static uint64_t tv_to_us(struct timeval *new)
{
    return (new->tv_sec * 1000000) + new->tv_usec;
}

static uint64_t llgettimeofday(void)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    return tv_to_us(&now);
}

static uint64_t tv_delta(struct timeval *new, struct timeval *old)
{
    return (((new->tv_sec - old->tv_sec)*1000000) +
            (new->tv_usec - old->tv_usec));
}

static int noncached_write(xc_interface *xch,
                           int fd, int live, void *buffer, int len) 
{
    static int write_count = 0;
    int rc = (write_exact(fd, buffer, len) == 0) ? len : -1;

    write_count += len;
    if ( write_count >= (MAX_PAGECACHE_USAGE * PAGE_SIZE) )
    {
        /* Time to discard cache - dont care if this fails */
        int saved_errno = errno;
        discard_file_cache(xch, fd, 0 /* no flush */);
        errno = saved_errno;
        write_count = 0;
    }

    return rc;
}

static int outbuf_init(xc_interface *xch, struct outbuf* ob, size_t size)
{
    memset(ob, 0, sizeof(*ob));

    if ( !(ob->buf = malloc(size)) ) {
        DPRINTF("error allocating output buffer of size %zu\n", size);
        return -1;
    }

    ob->size = size;

    return 0;
}

static inline int outbuf_write(xc_interface *xch,
                               struct outbuf* ob, void* buf, size_t len)
{
    if ( len > ob->size - ob->pos ) {
        DBGPRINTF("outbuf_write: %zu > %zu@%zu\n", len, ob->size - ob->pos, ob->pos);
        return -1;
    }

    memcpy(ob->buf + ob->pos, buf, len);
    ob->pos += len;

    return 0;
}

/* prep for nonblocking I/O */
static int outbuf_flush(xc_interface *xch, struct outbuf* ob, int fd)
{
    int rc;
    int cur = 0;

    if ( !ob->pos )
        return 0;

    rc = write(fd, ob->buf, ob->pos);
    while (rc < 0 || cur + rc < ob->pos) {
        if (rc < 0 && errno != EAGAIN && errno != EINTR) {
            DPRINTF("error flushing output: %d\n", errno);
            return -1;
        }
        if (rc > 0)
            cur += rc;

        rc = write(fd, ob->buf + cur, ob->pos - cur);
    }

    ob->pos = 0;

    return 0;
}

/* if there's no room in the buffer, flush it and try again. */
static inline int outbuf_hardwrite(xc_interface *xch,
                                   struct outbuf* ob, int fd, void* buf,
                                   size_t len)
{
    if ( !len )
        return 0;

    if ( !outbuf_write(xch, ob, buf, len) )
        return 0;

    if ( outbuf_flush(xch, ob, fd) < 0 )
        return -1;

    return outbuf_write(xch, ob, buf, len);
}

/* start buffering output once we've reached checkpoint mode. */
static inline int write_buffer(xc_interface *xch,
                               int dobuf, struct outbuf* ob, int fd, void* buf,
                               size_t len)
{
    if ( dobuf )
        return outbuf_hardwrite(xch, ob, fd, buf, len);
    else
        return write_exact(fd, buf, len);
}

#ifdef ADAPTIVE_SAVE

/*
** We control the rate at which we transmit (or save) to minimize impact
** on running domains (including the target if we're doing live migrate).
*/

#define MAX_MBIT_RATE    500      /* maximum transmit rate for migrate */
#define START_MBIT_RATE  100      /* initial transmit rate for migrate */

/* Scaling factor to convert between a rate (in Mb/s) and time (in usecs) */
#define RATE_TO_BTU      781250

/* Amount in bytes we allow ourselves to send in a burst */
#define BURST_BUDGET (100*1024)

/* We keep track of the current and previous transmission rate */
static int mbit_rate, ombit_rate = 0;

/* Have we reached the maximum transmission rate? */
#define RATE_IS_MAX() (mbit_rate == MAX_MBIT_RATE)

static inline void initialize_mbit_rate()
{
    mbit_rate = START_MBIT_RATE;
}

static int ratewrite(xc_interface *xch, int io_fd, int live, void *buf, int n)
{
    static int budget = 0;
    static int burst_time_us = -1;
    static struct timeval last_put = { 0 };
    struct timeval now;
    struct timespec delay;
    long long delta;

    if ( START_MBIT_RATE == 0 )
        return noncached_write(io_fd, live, buf, n);

    budget -= n;
    if ( budget < 0 )
    {
        if ( mbit_rate != ombit_rate )
        {
            burst_time_us = RATE_TO_BTU / mbit_rate;
            ombit_rate = mbit_rate;
            DPRINTF("rate limit: %d mbit/s burst budget %d slot time %d\n",
                    mbit_rate, BURST_BUDGET, burst_time_us);
        }
        if ( last_put.tv_sec == 0 )
        {
            budget += BURST_BUDGET;
            gettimeofday(&last_put, NULL);
        }
        else
        {
            while ( budget < 0 )
            {
                gettimeofday(&now, NULL);
                delta = tv_delta(&now, &last_put);
                while ( delta > burst_time_us )
                {
                    budget += BURST_BUDGET;
                    last_put.tv_usec += burst_time_us;
                    if ( last_put.tv_usec > 1000000 )
                    {
                        last_put.tv_usec -= 1000000;
                        last_put.tv_sec++;
                    }
                    delta -= burst_time_us;
                }
                if ( budget > 0 )
                    break;
                delay.tv_sec = 0;
                delay.tv_nsec = 1000 * (burst_time_us - delta);
                while ( delay.tv_nsec > 0 )
                    if ( nanosleep(&delay, &delay) == 0 )
                        break;
            }
        }
    }
    return noncached_write(io_fd, live, buf, n);
}

#else /* ! ADAPTIVE SAVE */

#define RATE_IS_MAX() (0)
#define ratewrite(xch, _io_fd, _live, _buf, _n) noncached_write((xch), (_io_fd), (_live), (_buf), (_n))
#define initialize_mbit_rate()

#endif

/* like write_buffer for ratewrite, which returns number of bytes written */
static inline int ratewrite_buffer(xc_interface *xch,
                                   int dobuf, struct outbuf* ob, int fd,
                                   int live, void* buf, size_t len)
{
    if ( dobuf )
        return outbuf_hardwrite(xch, ob, fd, buf, len) ? -1 : len;
    else
        return ratewrite(xch, fd, live, buf, len);
}

static int print_stats(xc_interface *xch, uint32_t domid, int pages_sent,
                       xc_shadow_op_stats_t *stats, int print)
{
    static struct timeval wall_last;
    static long long      d0_cpu_last;
    static long long      d1_cpu_last;

    struct timeval        wall_now;
    long long             wall_delta;
    long long             d0_cpu_now, d0_cpu_delta;
    long long             d1_cpu_now, d1_cpu_delta;

    gettimeofday(&wall_now, NULL);

    d0_cpu_now = xc_domain_get_cpu_usage(xch, 0, /* FIXME */ 0)/1000;
    d1_cpu_now = xc_domain_get_cpu_usage(xch, domid, /* FIXME */ 0)/1000;

    if ( (d0_cpu_now == -1) || (d1_cpu_now == -1) )
        DPRINTF("ARRHHH!!\n");

    wall_delta = tv_delta(&wall_now,&wall_last)/1000;
    if ( wall_delta == 0 )
        wall_delta = 1;

    d0_cpu_delta = (d0_cpu_now - d0_cpu_last)/1000;
    d1_cpu_delta = (d1_cpu_now - d1_cpu_last)/1000;

    if ( print )
        DPRINTF("delta %lldms, dom0 %d%%, target %d%%, sent %dMb/s, "
                "dirtied %dMb/s %" PRId32 " pages\n",
                wall_delta,
                (int)((d0_cpu_delta*100)/wall_delta),
                (int)((d1_cpu_delta*100)/wall_delta),
                (int)((pages_sent*PAGE_SIZE)/(wall_delta*(1000/8))),
                (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))),
                stats->dirty_count);

#ifdef ADAPTIVE_SAVE
    if ( ((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8))) > mbit_rate )
    {
        mbit_rate = (int)((stats->dirty_count*PAGE_SIZE)/(wall_delta*(1000/8)))
            + 50;
        if ( mbit_rate > MAX_MBIT_RATE )
            mbit_rate = MAX_MBIT_RATE;
    }
#endif

    d0_cpu_last = d0_cpu_now;
    d1_cpu_last = d1_cpu_now;
    wall_last   = wall_now;

    return 0;
}


static int analysis_phase(xc_interface *xch, uint32_t domid, struct save_ctx *ctx,
                          xc_hypercall_buffer_t *arr, int runs)
{
    long long start, now;
    xc_shadow_op_stats_t stats;
    int j;
    struct domain_info_context *dinfo = &ctx->dinfo;

    start = llgettimeofday();

    for ( j = 0; j < runs; j++ )
    {
        int i;

        xc_shadow_control(xch, domid, XEN_DOMCTL_SHADOW_OP_CLEAN,
                          arr, dinfo->p2m_size, NULL, 0, NULL);
        DPRINTF("#Flush\n");
        for ( i = 0; i < 40; i++ )
        {
            usleep(50000);
            now = llgettimeofday();
            xc_shadow_control(xch, domid, XEN_DOMCTL_SHADOW_OP_PEEK,
                              NULL, 0, NULL, 0, &stats);
            DPRINTF("now= %lld faults= %"PRId32" dirty= %"PRId32"\n",
                    ((now-start)+500)/1000,
                    stats.fault_count, stats.dirty_count);
        }
    }

    return -1;
}

static int suspend_and_state(int (*suspend)(void*), void* data,
                             xc_interface *xch, int io_fd, int dom,
                             xc_dominfo_t *info)
{
    if ( !(*suspend)(data) )
    {
        ERROR("Suspend request failed");
        return -1;
    }

    if ( (xc_domain_getinfo(xch, dom, 1, info) != 1) ||
         !info->shutdown || (info->shutdown_reason != SHUTDOWN_suspend) )
    {
        ERROR("Domain not in suspended state");
        return -1;
    }

    return 0;
}

/*
** Map the top-level page of MFNs from the guest. The guest might not have
** finished resuming from a previous restore operation, so we wait a while for
** it to update the MFN to a reasonable value.
*/
static void *map_frame_list_list(xc_interface *xch, uint32_t dom,
                                 struct save_ctx *ctx,
                                 shared_info_any_t *shinfo)
{
    int count = 100;
    void *p;
    struct domain_info_context *dinfo = &ctx->dinfo;
    uint64_t fll = GET_FIELD(shinfo, arch.pfn_to_mfn_frame_list_list);

    while ( count-- && (fll == 0) )
    {
        usleep(10000);
        fll = GET_FIELD(shinfo, arch.pfn_to_mfn_frame_list_list);
    }

    if ( fll == 0 )
    {
        ERROR("Timed out waiting for frame list updated.");
        return NULL;
    }

    p = xc_map_foreign_range(xch, dom, PAGE_SIZE, PROT_READ, fll);
    if ( p == NULL )
        PERROR("Couldn't map p2m_frame_list_list (errno %d)", errno);

    return p;
}

/*
** During transfer (or in the state file), all page-table pages must be
** converted into a 'canonical' form where references to actual mfns
** are replaced with references to the corresponding pfns.
**
** This function performs the appropriate conversion, taking into account
** which entries do not require canonicalization (in particular, those
** entries which map the virtual address reserved for the hypervisor).
*/
static int canonicalize_pagetable(struct save_ctx *ctx,
                           unsigned long type, unsigned long pfn,
                           const void *spage, void *dpage)
{
    struct domain_info_context *dinfo = &ctx->dinfo;
    int i, pte_last, xen_start, xen_end, race = 0; 
    uint64_t pte;

    /*
    ** We need to determine which entries in this page table hold
    ** reserved hypervisor mappings. This depends on the current
    ** page table type as well as the number of paging levels.
    */
    xen_start = xen_end = pte_last = PAGE_SIZE / ((ctx->pt_levels == 2) ? 4 : 8);

    if ( (ctx->pt_levels == 2) && (type == XEN_DOMCTL_PFINFO_L2TAB) )
        xen_start = (ctx->hvirt_start >> L2_PAGETABLE_SHIFT);

    if ( (ctx->pt_levels == 3) && (type == XEN_DOMCTL_PFINFO_L3TAB) )
        xen_start = L3_PAGETABLE_ENTRIES_PAE;

    /*
    ** In PAE only the L2 mapping the top 1GB contains Xen mappings.
    ** We can spot this by looking for the guest's mappingof the m2p.
    ** Guests must ensure that this check will fail for other L2s.
    */
    if ( (ctx->pt_levels == 3) && (type == XEN_DOMCTL_PFINFO_L2TAB) )
    {
        int hstart;
        uint64_t he;

        hstart = (ctx->hvirt_start >> L2_PAGETABLE_SHIFT_PAE) & 0x1ff;
        he = ((const uint64_t *) spage)[hstart];

        if ( ((he >> PAGE_SHIFT) & MFN_MASK_X86) == ctx->m2p_mfn0 )
        {
            /* hvirt starts with xen stuff... */
            xen_start = hstart;
        }
        else if ( ctx->hvirt_start != 0xf5800000 )
        {
            /* old L2s from before hole was shrunk... */
            hstart = (0xf5800000 >> L2_PAGETABLE_SHIFT_PAE) & 0x1ff;
            he = ((const uint64_t *) spage)[hstart];
            if ( ((he >> PAGE_SHIFT) & MFN_MASK_X86) == ctx->m2p_mfn0 )
                xen_start = hstart;
        }
    }

    if ( (ctx->pt_levels == 4) && (type == XEN_DOMCTL_PFINFO_L4TAB) )
    {
        /*
        ** XXX SMH: should compute these from hvirt_start (which we have)
        ** and hvirt_end (which we don't)
        */
        xen_start = 256;
        xen_end   = 272;
    }

    /* Now iterate through the page table, canonicalizing each PTE */
    for (i = 0; i < pte_last; i++ )
    {
        unsigned long pfn, mfn;

        if ( ctx->pt_levels == 2 )
            pte = ((const uint32_t*)spage)[i];
        else
            pte = ((const uint64_t*)spage)[i];

        if ( (i >= xen_start) && (i < xen_end) )
            pte = 0;

        if ( pte & _PAGE_PRESENT )
        {
            mfn = (pte >> PAGE_SHIFT) & MFN_MASK_X86;
            if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
            {
                /* This will happen if the type info is stale which
                   is quite feasible under live migration */
                pfn  = 0;  /* zap it - we'll retransmit this page later */
                /* XXX: We can't spot Xen mappings in compat-mode L2es 
                 * from 64-bit tools, but the only thing in them is the
                 * compat m2p, so we quietly zap them.  This doesn't
                 * count as a race, so don't report it. */
                if ( !(type == XEN_DOMCTL_PFINFO_L2TAB 
                       && sizeof (unsigned long) > dinfo->guest_width) )
                     race = 1;  /* inform the caller; fatal if !live */ 
            }
            else
                pfn = mfn_to_pfn(mfn);

            pte &= ~MADDR_MASK_X86;
            pte |= (uint64_t)pfn << PAGE_SHIFT;

            /*
             * PAE guest L3Es can contain these flags when running on
             * a 64bit hypervisor. We zap these here to avoid any
             * surprise at restore time...
             */
            if ( (ctx->pt_levels == 3) &&
                 (type == XEN_DOMCTL_PFINFO_L3TAB) &&
                 (pte & (_PAGE_USER|_PAGE_RW|_PAGE_ACCESSED)) )
                pte &= ~(_PAGE_USER|_PAGE_RW|_PAGE_ACCESSED);
        }

        if ( ctx->pt_levels == 2 )
            ((uint32_t*)dpage)[i] = pte;
        else
            ((uint64_t*)dpage)[i] = pte;
    }

    return race;
}

xen_pfn_t *xc_map_m2p(xc_interface *xch,
                                 unsigned long max_mfn,
                                 int prot,
                                 unsigned long *mfn0)
{
    privcmd_mmap_entry_t *entries;
    unsigned long m2p_chunks, m2p_size;
    xen_pfn_t *m2p;
    xen_pfn_t *extent_start;
    int i;

    m2p = NULL;
    m2p_size   = M2P_SIZE(max_mfn);
    m2p_chunks = M2P_CHUNKS(max_mfn);

    extent_start = calloc(m2p_chunks, sizeof(xen_pfn_t));
    if ( !extent_start )
    {
        ERROR("failed to allocate space for m2p mfns");
        goto err0;
    }

    if ( xc_machphys_mfn_list(xch, m2p_chunks, extent_start) )
    {
        PERROR("xc_get_m2p_mfns");
        goto err1;
    }

    entries = calloc(m2p_chunks, sizeof(privcmd_mmap_entry_t));
    if (entries == NULL)
    {
        ERROR("failed to allocate space for mmap entries");
        goto err1;
    }

    for ( i = 0; i < m2p_chunks; i++ )
        entries[i].mfn = extent_start[i];

    m2p = xc_map_foreign_ranges(xch, DOMID_XEN,
			m2p_size, prot, M2P_CHUNK_SIZE,
			entries, m2p_chunks);
    if (m2p == NULL)
    {
        PERROR("xc_mmap_foreign_ranges failed");
        goto err2;
    }

    if (mfn0)
        *mfn0 = entries[0].mfn;

err2:
    free(entries);
err1:
    free(extent_start);

err0:
    return m2p;
}


static xen_pfn_t *map_and_save_p2m_table(xc_interface *xch, 
                                         int io_fd, 
                                         uint32_t dom,
                                         struct save_ctx *ctx,
                                         shared_info_any_t *live_shinfo)
{
    vcpu_guest_context_any_t ctxt;
    struct domain_info_context *dinfo = &ctx->dinfo;

    /* Double and single indirect references to the live P2M table */
    void *live_p2m_frame_list_list = NULL;
    void *live_p2m_frame_list = NULL;

    /* Copies of the above. */
    xen_pfn_t *p2m_frame_list_list = NULL;
    xen_pfn_t *p2m_frame_list = NULL;

    /* The mapping of the live p2m table itself */
    xen_pfn_t *p2m = NULL;

    int i, success = 0;

    live_p2m_frame_list_list = map_frame_list_list(xch, dom, ctx,
                                                   live_shinfo);
    if ( !live_p2m_frame_list_list )
        goto out;

    /* Get a local copy of the live_P2M_frame_list_list */
    if ( !(p2m_frame_list_list = malloc(PAGE_SIZE)) )
    {
        ERROR("Couldn't allocate p2m_frame_list_list array");
        goto out;
    }
    memcpy(p2m_frame_list_list, live_p2m_frame_list_list, PAGE_SIZE);

    /* Canonicalize guest's unsigned long vs ours */
    if ( dinfo->guest_width > sizeof(unsigned long) )
        for ( i = 0; i < PAGE_SIZE/sizeof(unsigned long); i++ )
            if ( i < PAGE_SIZE/dinfo->guest_width )
                p2m_frame_list_list[i] = ((uint64_t *)p2m_frame_list_list)[i];
            else
                p2m_frame_list_list[i] = 0;
    else if ( dinfo->guest_width < sizeof(unsigned long) )
        for ( i = PAGE_SIZE/sizeof(unsigned long) - 1; i >= 0; i-- )
            p2m_frame_list_list[i] = ((uint32_t *)p2m_frame_list_list)[i];

    live_p2m_frame_list =
        xc_map_foreign_pages(xch, dom, PROT_READ,
                             p2m_frame_list_list,
                             P2M_FLL_ENTRIES);
    if ( !live_p2m_frame_list )
    {
        PERROR("Couldn't map p2m_frame_list");
        goto out;
    }

    /* Get a local copy of the live_P2M_frame_list */
    if ( !(p2m_frame_list = malloc(P2M_TOOLS_FL_SIZE)) )
    {
        ERROR("Couldn't allocate p2m_frame_list array");
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


    /* Map all the frames of the pfn->mfn table. For migrate to succeed,
       the guest must not change which frames are used for this purpose.
       (its not clear why it would want to change them, and we'll be OK
       from a safety POV anyhow. */

    p2m = xc_map_foreign_pages(xch, dom, PROT_READ,
                               p2m_frame_list,
                               P2M_FL_ENTRIES);
    if ( !p2m )
    {
        PERROR("Couldn't map p2m table");
        goto out;
    }
    ctx->live_p2m = p2m; /* So that translation macros will work */
    
    /* Canonicalise the pfn-to-mfn table frame-number list. */
    for ( i = 0; i < dinfo->p2m_size; i += FPP )
    {
        if ( !MFN_IS_IN_PSEUDOPHYS_MAP(p2m_frame_list[i/FPP]) )
        {
            ERROR("Frame# in pfn-to-mfn frame list is not in pseudophys");
            ERROR("entry %d: p2m_frame_list[%ld] is 0x%"PRIx64", max 0x%lx",
                  i, i/FPP, (uint64_t)p2m_frame_list[i/FPP], ctx->max_mfn);
            if ( p2m_frame_list[i/FPP] < ctx->max_mfn ) 
            {
                ERROR("m2p[0x%"PRIx64"] = 0x%"PRIx64, 
                      (uint64_t)p2m_frame_list[i/FPP],
                      (uint64_t)ctx->live_m2p[p2m_frame_list[i/FPP]]);
                ERROR("p2m[0x%"PRIx64"] = 0x%"PRIx64, 
                      (uint64_t)ctx->live_m2p[p2m_frame_list[i/FPP]],
                      (uint64_t)p2m[ctx->live_m2p[p2m_frame_list[i/FPP]]]);

            }
            goto out;
        }
        p2m_frame_list[i/FPP] = mfn_to_pfn(p2m_frame_list[i/FPP]);
    }

    if ( xc_vcpu_getcontext(xch, dom, 0, &ctxt) )
    {
        PERROR("Could not get vcpu context");
        goto out;
    }

    /*
     * Write an extended-info structure to inform the restore code that
     * a PAE guest understands extended CR3 (PDPTs above 4GB). Turns off
     * slow paths in the restore code.
     */
    {
        unsigned long signature = ~0UL;
        uint32_t chunk1_sz = ((dinfo->guest_width==8) 
                              ? sizeof(ctxt.x64) 
                              : sizeof(ctxt.x32));
        uint32_t chunk2_sz = 0;
        uint32_t chunk3_sz = 4;
        uint32_t xcnt_size = 0;
        uint32_t tot_sz;
        DECLARE_DOMCTL;

        domctl.cmd = XEN_DOMCTL_getvcpuextstate;
        domctl.domain = dom;
        domctl.u.vcpuextstate.vcpu = 0;
        domctl.u.vcpuextstate.size = 0;
        domctl.u.vcpuextstate.xfeature_mask = 0;
        if ( xc_domctl(xch, &domctl) < 0 )
        {
            PERROR("No extended context for VCPU%d", i);
            goto out;
        }
        xcnt_size = domctl.u.vcpuextstate.size + 2 * sizeof(uint64_t);

        tot_sz = (chunk1_sz + 8) + (chunk2_sz + 8);
        if ( domctl.u.vcpuextstate.xfeature_mask )
            tot_sz += chunk3_sz + 8;

        if ( write_exact(io_fd, &signature, sizeof(signature)) ||
             write_exact(io_fd, &tot_sz, sizeof(tot_sz)) ||
             write_exact(io_fd, "vcpu", 4) ||
             write_exact(io_fd, &chunk1_sz, sizeof(chunk1_sz)) ||
             write_exact(io_fd, &ctxt, chunk1_sz) ||
             write_exact(io_fd, "extv", 4) ||
             write_exact(io_fd, &chunk2_sz, sizeof(chunk2_sz)) ||
             (domctl.u.vcpuextstate.xfeature_mask) ?
                (write_exact(io_fd, "xcnt", 4) ||
                write_exact(io_fd, &chunk3_sz, sizeof(chunk3_sz)) ||
                write_exact(io_fd, &xcnt_size, 4)) :
                0 )
        {
            PERROR("write: extended info");
            goto out;
        }
    }

    if ( write_exact(io_fd, p2m_frame_list, 
                     P2M_FL_ENTRIES * sizeof(xen_pfn_t)) )
    {
        PERROR("write: p2m_frame_list");
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

/* must be done AFTER suspend_and_state() */
static int save_tsc_info(xc_interface *xch, uint32_t dom, int io_fd)
{
    int marker = XC_SAVE_ID_TSC_INFO;
    uint32_t tsc_mode, khz, incarn;
    uint64_t nsec;

    if ( xc_domain_get_tsc_info(xch, dom, &tsc_mode,
                                &nsec, &khz, &incarn) < 0  ||
         write_exact(io_fd, &marker, sizeof(marker)) ||
         write_exact(io_fd, &tsc_mode, sizeof(tsc_mode)) ||
         write_exact(io_fd, &nsec, sizeof(nsec)) ||
         write_exact(io_fd, &khz, sizeof(khz)) ||
         write_exact(io_fd, &incarn, sizeof(incarn)) )
        return -1;
    return 0;
}

#ifdef NET_FW
static void start_input_network(void)
{
	pid_t pid;

	pid = vfork();
	if (pid > 0) { // father wait child exit
		wait(NULL);
		return;
	}

	execl("/etc/xen/scripts/HA_fw_runtime.sh", "HA_fw_runtime.sh", "input", NULL);
}
#endif
#ifdef FAILOVER
static void failover(void)
{
	pid_t pid;

	pid = vfork();
	if (pid > 0) {
		wait(NULL);
		return;
	}
	
	execl("/etc/xen/scripts/failover_master.sh", "failover_master.sh", NULL);
}
#endif

#ifdef NET_FW
static void install_fw_network(void)
{
	pid_t pid;

	pid = vfork();
	if (pid > 0) { // father wait child exit
		wait(NULL);
		return;
	}

	execl("/etc/xen/scripts/HA_fw_runtime.sh", "HA_fw_runtime.sh", "install", NULL);
}
#endif
/*static void uninstall_fw_network(void)
{
	pid_t pid;

	pid = vfork();
	if (pid > 0) { // father wait child exit
		wait(NULL);
		return;
	}

	execl("/etc/xen/scripts/HA_fw_runtime.sh", "HA_fw_runtime.sh", "uninstall", NULL);
}
*/

/* big cache to avoid future map */
static char **pages_base;

static int colo_ro_map_and_cache(xc_interface *xch, uint32_t dom,
	unsigned long *pfn_batch, xen_pfn_t *pfn_type, int *pfn_err, int batch)
{
    static xen_pfn_t cache_pfn_type[MAX_BATCH_SIZE];
    static int cache_pfn_err[MAX_BATCH_SIZE];
    int i, cache_batch = 0;
    char *map;

    for (i = 0; i < batch; i++) {
	if (!pages_base[pfn_batch[i]])
		cache_pfn_type[cache_batch++] = pfn_type[i];
    }

    if (cache_batch) {
        map = xc_map_foreign_bulk(xch, dom, PROT_READ, cache_pfn_type, cache_pfn_err, cache_batch);
	if (!map)
		return -1;
    }

    cache_batch = 0;
    for (i = 0; i < batch; i++) {
	if (pages_base[pfn_batch[i]]) {
		pfn_err[i] = 0;
	} else {
		if (!cache_pfn_err[cache_batch])
			pages_base[pfn_batch[i]] = map + PAGE_SIZE * cache_batch;
		pfn_err[i] = cache_pfn_err[cache_batch];
		cache_batch++;
	}
    }

    return 0;
}

int xc_domain_save(xc_interface *xch, int io_fd, uint32_t dom, uint32_t max_iters,
                   uint32_t max_factor, uint32_t flags,
                   struct save_callbacks* callbacks, int hvm)
{
    xc_dominfo_t info;
    DECLARE_DOMCTL;

    int rc = 1, frc, i, j, last_iter = 0, iter = 0;
    int live  = (flags & XCFLAGS_LIVE);
    int debug = (flags & XCFLAGS_DEBUG);
    int race = 0, sent_last_iter, skip_this_iter = 0;
    unsigned int sent_this_iter = 0;
    int tmem_saved = 0;

    /* The new domain's shared-info frame number. */
    unsigned long shared_info_frame;

    /* A copy of the CPU context of the guest. */
    vcpu_guest_context_any_t ctxt;

    /* A table containing the type of each PFN (/not/ MFN!). */
    xen_pfn_t *pfn_type = NULL;
    unsigned long *pfn_batch = NULL;
    int *pfn_err = NULL;

    /* A copy of one frame of guest memory. */
    char page[PAGE_SIZE];

    /* Live mapping of shared info structure */
    shared_info_any_t *live_shinfo = NULL;

    /* base of the region in which domain memory is mapped */
    unsigned char *region_base = NULL;

    /* A copy of the CPU eXtended States of the guest. */
    DECLARE_HYPERCALL_BUFFER(void, buffer);

    /* bitmap of pages:
       - that should be sent this iteration (unless later marked as skip);
       - to skip this iteration because already dirty;
       - to fixup by sending at the end if not already resent; */
    DECLARE_HYPERCALL_BUFFER(unsigned long, to_skip);
    DECLARE_HYPERCALL_BUFFER(unsigned long, to_send);
    unsigned long *to_fix = NULL;

    xc_shadow_op_stats_t stats;

    unsigned long needed_to_fix = 0;
    unsigned long total_sent    = 0;

    uint64_t vcpumap = 1ULL;

    /* HVM: a buffer for holding HVM context */
    uint32_t hvm_buf_size = 0;
    uint8_t *hvm_buf = NULL;

    /* HVM: magic frames for ioreqs and xenstore comms. */
    uint64_t magic_pfns[3]; /* ioreq_pfn, bufioreq_pfn, store_pfn */

    unsigned long mfn;

    struct outbuf ob;
    static struct save_ctx _ctx = {
        .live_p2m = NULL,
        .live_m2p = NULL,
    };
    static struct save_ctx *ctx = &_ctx;
    struct domain_info_context *dinfo = &ctx->dinfo;

    int completed = 0;
    int first_time = 1;

    char sig_buf[20];
    int err;
    struct timeval tv;
    fd_set rfds;
    int want_exit = 0;

    FILE *stat_fp;

    stat_fp = fopen("/root/yewei/master.txt", "at");
    setbuf(stat_fp, NULL);
    setlinebuf(stdout);

    syscall(NR_reset_suspend_count);
    syscall(NR_vif_block, 0);

    if ( hvm && !callbacks->switch_qemu_logdirty )
    {
        ERROR("No switch_qemu_logdirty callback provided.");
        errno = EINVAL;
        return 1;
    }

    outbuf_init(xch, &ob, OUTBUF_SIZE);

    /* If no explicit control parameters given, use defaults */
    max_iters  = max_iters  ? : DEF_MAX_ITERS;
    max_factor = max_factor ? : DEF_MAX_FACTOR;

    initialize_mbit_rate();

    if ( !get_platform_info(xch, dom,
                            &ctx->max_mfn, &ctx->hvirt_start, &ctx->pt_levels, &dinfo->guest_width) )
    {
        ERROR("Unable to get platform info.");
        return 1;
    }

    if ( xc_domain_getinfo(xch, dom, 1, &info) != 1 )
    {
        PERROR("Could not get domain info");
        return 1;
    }

    shared_info_frame = info.shared_info_frame;

    /* Map the shared info frame */
    if ( !hvm )
    {
        live_shinfo = xc_map_foreign_range(xch, dom, PAGE_SIZE,
                                           PROT_READ, shared_info_frame);
        if ( !live_shinfo )
        {
            PERROR("Couldn't map live_shinfo");
            goto out;
        }
    }

    /* Get the size of the P2M table */
    dinfo->p2m_size = xc_domain_maximum_gpfn(xch, dom) + 1;

    if ( dinfo->p2m_size > ~XEN_DOMCTL_PFINFO_LTAB_MASK )
    {
        ERROR("Cannot save this big a guest");
        goto out;
    }

    /* Domain is still running at this point */
    if ( live )
    {
        /* Live suspend. Enable log-dirty mode. */
        if ( xc_shadow_control(xch, dom,
                               XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY,
                               NULL, 0, NULL, 0, NULL) < 0 )
        {
            /* log-dirty already enabled? There's no test op,
               so attempt to disable then reenable it */
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
                PERROR("Couldn't enable shadow mode (rc %d) (errno %d)", frc, errno );
                goto out;
            }
        }

        /* Enable qemu-dm logging dirty pages to xen */
        if ( hvm && callbacks->switch_qemu_logdirty(dom, 1, callbacks->data) )
        {
            PERROR("Couldn't enable qemu log-dirty mode (errno %d)", errno);
            goto out;
        }
    }
    else
    {
        /* This is a non-live suspend. Suspend the domain .*/
        if ( suspend_and_state(callbacks->suspend, callbacks->data, xch,
                               io_fd, dom, &info) )
        {
            ERROR("Domain appears not to have suspended");
            goto out;
        }
    }

    last_iter = !live;

    /* pretend we sent all the pages last iteration */
    sent_last_iter = dinfo->p2m_size;

    /* Setup to_send / to_fix and to_skip bitmaps */
    to_send = xc_hypercall_buffer_alloc_pages(xch, to_send, NRPAGES(BITMAP_SIZE));
    to_skip = xc_hypercall_buffer_alloc_pages(xch, to_skip, NRPAGES(BITMAP_SIZE));
    to_fix  = calloc(1, BITMAP_SIZE);

    if ( !to_send || !to_fix || !to_skip )
    {
        ERROR("Couldn't allocate to_send array");
        goto out;
    }

    memset(to_send, 0xff, BITMAP_SIZE);

    if ( hvm )
    {
        /* Need another buffer for HVM context */
        hvm_buf_size = xc_domain_hvm_getcontext(xch, dom, 0, 0);
        if ( hvm_buf_size == -1 )
        {
            PERROR("Couldn't get HVM context size from Xen");
            goto out;
        }
        hvm_buf = malloc(hvm_buf_size);
        if ( !hvm_buf )
        {
            ERROR("Couldn't allocate memory");
            goto out;
        }
    }

    analysis_phase(xch, dom, ctx, HYPERCALL_BUFFER(to_skip), 0);

    pages_base = calloc(dinfo->p2m_size, sizeof(*pages_base));
    pfn_type   = malloc(ROUNDUP(MAX_BATCH_SIZE * sizeof(*pfn_type), PAGE_SHIFT));
    pfn_batch  = calloc(MAX_BATCH_SIZE, sizeof(*pfn_batch));
    pfn_err    = malloc(MAX_BATCH_SIZE * sizeof(*pfn_err));
    if ( (pages_base == NULL) || (pfn_type == NULL) || (pfn_batch == NULL) || (pfn_err == NULL) )
    {
        ERROR("failed to alloc memory for pfn_type and/or pfn_batch arrays");
        errno = ENOMEM;
        goto out;
    }
    memset(pfn_type, 0,
           ROUNDUP(MAX_BATCH_SIZE * sizeof(*pfn_type), PAGE_SHIFT));

    /* Setup the mfn_to_pfn table mapping */
    if ( !(ctx->live_m2p = xc_map_m2p(xch, ctx->max_mfn, PROT_READ, &ctx->m2p_mfn0)) )
    {
        PERROR("Failed to map live M2P table");
        goto out;
    }

    /* Start writing out the saved-domain record. */
    if ( write_exact(io_fd, &dinfo->p2m_size, sizeof(unsigned long)) )
    {
        PERROR("write: p2m_size");
        goto out;
    }

    if ( !hvm )
    {
        int err = 0;

        /* Map the P2M table, and write the list of P2M frames */
        ctx->live_p2m = map_and_save_p2m_table(xch, io_fd, dom, ctx, live_shinfo);
        if ( ctx->live_p2m == NULL )
        {
            PERROR("Failed to map/save the p2m frame list");
            goto out;
        }

        /*
         * Quick belt and braces sanity check.
         */
        
        for ( i = 0; i < dinfo->p2m_size; i++ )
        {
            mfn = pfn_to_mfn(i);
            if( (mfn != INVALID_P2M_ENTRY) && (mfn_to_pfn(mfn) != i) )
            {
                DPRINTF("i=0x%x mfn=%lx live_m2p=%lx\n", i,
                        mfn, mfn_to_pfn(mfn));
                err++;
            }
        }
        DPRINTF("Had %d unexplained entries in p2m table\n", err);
    }

    print_stats(xch, dom, 0, &stats, 0);

    tmem_saved = xc_tmem_save(xch, dom, io_fd, live, XC_SAVE_ID_TMEM);
    if ( tmem_saved == -1 )
    {
        PERROR("Error when writing to state file (tmem)");
        goto out;
    }

    if ( !live && save_tsc_info(xch, dom, io_fd) < 0 )
    {
        PERROR("Error when writing to state file (tsc)");
        goto out;
    }

  copypages:
#define wrexact(fd, buf, len) write_buffer(xch, last_iter, &ob, (fd), (buf), (len))
#ifdef ratewrite
#undef ratewrite
#endif
#define ratewrite(fd, live, buf, len) ratewrite_buffer(xch, last_iter, &ob, (fd), (live), (buf), (len))

    gettimeofday(&tv, NULL);
    printf("\n[%lu.%06lu]page transmit start.\n", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec);

    
    fprintf(stat_fp, "%lu.%06lu\t", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
    /* Now write out each data page, canonicalising page tables as we go... */
    for ( ; ; )
    {
        unsigned int N, batch, run;
        char reportbuf[80];

        snprintf(reportbuf, sizeof(reportbuf),
                 "Saving memory: iter %d (last sent %u skipped %u)",
                 iter, sent_this_iter, skip_this_iter);

        xc_report_progress_start(xch, reportbuf, dinfo->p2m_size);

        iter++;
        sent_this_iter = 0;
        skip_this_iter = 0;
        N = 0;

        while ( N < dinfo->p2m_size )
        {
            xc_report_progress_step(xch, N, dinfo->p2m_size);

            if ( !last_iter )
            {
                /* Slightly wasteful to peek the whole array every time,
                   but this is fast enough for the moment. */
                frc = xc_shadow_control(
                    xch, dom, XEN_DOMCTL_SHADOW_OP_PEEK, HYPERCALL_BUFFER(to_skip),
                    dinfo->p2m_size, NULL, 0, NULL);
                if ( frc != dinfo->p2m_size )
                {
                    ERROR("Error peeking shadow bitmap");
                    goto out;
                }
            }

            /* load pfn_type[] with the mfn of all the pages we're doing in
               this batch. */
            for  ( batch = 0;
                   (batch < MAX_BATCH_SIZE) && (N < dinfo->p2m_size);
                   N++ )
            {
                int n = N;

                if ( debug )
                {
                    DPRINTF("%d pfn= %08lx mfn= %08lx %d",
                            iter, (unsigned long)n,
                            hvm ? 0 : pfn_to_mfn(n),
                            test_bit(n, to_send));
                    if ( !hvm && is_mapped(pfn_to_mfn(n)) )
                        DPRINTF("  [mfn]= %08lx",
                                mfn_to_pfn(pfn_to_mfn(n)&0xFFFFF));
                    DPRINTF("\n");
                }

                if ( completed )
                {
                    /* for sparse bitmaps, word-by-word may save time */
                    if ( !to_send[N >> ORDER_LONG] )
                    {
                        /* incremented again in for loop! */
                        N += BITS_PER_LONG - 1;
                        continue;
                    }

                    if ( !test_bit(n, to_send) )
                        continue;

                    pfn_batch[batch] = n;
                    if ( hvm )
                        pfn_type[batch] = n;
                    else
                        pfn_type[batch] = pfn_to_mfn(n);
                }
                else
                {
                    if ( !last_iter &&
                         test_bit(n, to_send) &&
                         test_bit(n, to_skip) )
                        skip_this_iter++; /* stats keeping */

                    if ( !((test_bit(n, to_send) && !test_bit(n, to_skip)) ||
                           (test_bit(n, to_send) && last_iter) ||
                           (test_bit(n, to_fix)  && last_iter)) )
                        continue;

                    /*
                    ** we get here if:
                    **  1. page is marked to_send & hasn't already been re-dirtied
                    **  2. (ignore to_skip in last iteration)
                    **  3. add in pages that still need fixup (net bufs)
                    */

                    pfn_batch[batch] = n;

                    /* Hypercall interfaces operate in PFNs for HVM guests
                     * and MFNs for PV guests */
                    if ( hvm )
                        pfn_type[batch] = n;
                    else
                        pfn_type[batch] = pfn_to_mfn(n);
                    
                    if ( !is_mapped(pfn_type[batch]) )
                    {
                        /*
                        ** not currently in psuedo-physical map -- set bit
                        ** in to_fix since we must send this page in last_iter
                        ** unless its sent sooner anyhow, or it never enters
                        ** pseudo-physical map (e.g. for ballooned down doms)
                        */
                        set_bit(n, to_fix);
                        continue;
                    }

                    if ( last_iter &&
                         test_bit(n, to_fix) &&
                         !test_bit(n, to_send) )
                    {
                        needed_to_fix++;
                        DPRINTF("Fix! iter %d, pfn %x. mfn %lx\n",
                                iter, n, pfn_type[batch]);
                    }

                    clear_bit(n, to_fix);
                }
                
                batch++;
            }

            if ( batch == 0 )
                goto skip; /* vanishingly unlikely... */

	    if (colo_ro_map_and_cache(xch, dom, pfn_batch, pfn_type, pfn_err, batch) < 0)
            {
                PERROR("map batch failed");
                goto out;
            }

            /* Get page types */
            if ( xc_get_pfn_type_batch(xch, dom, batch, pfn_type) )
            {
                PERROR("get_pfn_type_batch failed");
                goto out;
            }

            for ( run = j = 0; j < batch; j++ )
            {
                unsigned long gmfn = pfn_batch[j];

                if ( !hvm )
                    gmfn = pfn_to_mfn(gmfn);

                if ( pfn_err[j] )
                {
                    if ( pfn_type[j] == XEN_DOMCTL_PFINFO_XTAB )
                        continue;
                    DPRINTF("map fail: page %i mfn %08lx err %d\n",
                            j, gmfn, pfn_err[j]);
                    pfn_type[j] = XEN_DOMCTL_PFINFO_XTAB;
                    continue;
                }

                if ( pfn_type[j] == XEN_DOMCTL_PFINFO_XTAB )
                {
                    DPRINTF("type fail: page %i mfn %08lx\n", j, gmfn);
                    continue;
                }

                /* canonicalise mfn->pfn */
                pfn_type[j] |= pfn_batch[j];
                ++run;

                if ( debug )
                {
                    if ( hvm )
                        DPRINTF("%d pfn=%08lx sum=%08lx\n",
                                iter,
                                pfn_type[j],
                                csum_page(pages_base[pfn_batch[j]]));
                    else
                        DPRINTF("%d pfn= %08lx mfn= %08lx [mfn]= %08lx"
                                " sum= %08lx\n",
                                iter,
                                pfn_type[j],
                                gmfn,
                                mfn_to_pfn(gmfn),
                                csum_page(pages_base[pfn_batch[j]]));
                }
            }

            if ( !run )
            {
                //munmap(region_base, batch*PAGE_SIZE);
                continue; /* bail on this batch: no valid pages */
            }

            if ( wrexact(io_fd, &batch, sizeof(unsigned int)) )
            {
                PERROR("Error when writing to state file (2)");
                goto out;
            }

            if ( sizeof(unsigned long) < sizeof(*pfn_type) )
                for ( j = 0; j < batch; j++ )
                    ((unsigned long *)pfn_type)[j] = pfn_type[j];
            if ( wrexact(io_fd, pfn_type, sizeof(unsigned long)*batch) )
            {
                PERROR("Error when writing to state file (3)");
                goto out;
            }
            if ( sizeof(unsigned long) < sizeof(*pfn_type) )
                while ( --j >= 0 )
                    pfn_type[j] = ((unsigned long *)pfn_type)[j];

            /* entering this loop, pfn_type is now in pfns (Not mfns) */
            run = 0;
            for ( j = 0; j < batch; j++ )
            {
                unsigned long pfn, pagetype;
                void *spage = pages_base[pfn_batch[j]];

                pfn      = pfn_type[j] & ~XEN_DOMCTL_PFINFO_LTAB_MASK;
                pagetype = pfn_type[j] &  XEN_DOMCTL_PFINFO_LTAB_MASK;

                if ( pagetype != 0 )
                {
                    /* If the page is not a normal data page, write out any
                       run of pages we may have previously acumulated */
                    if ( run )
                    {
                        if ( ratewrite(io_fd, live, 
                                       (char*)region_base+(PAGE_SIZE*(j-run)), 
                                       PAGE_SIZE*run) != PAGE_SIZE*run )
                        {
                            PERROR("Error when writing to state file (4a)"
                                  " (errno %d)", errno);
                            goto out;
                        }                        
                        run = 0;
                    }
                }

                /* skip pages that aren't present */
                if ( pagetype == XEN_DOMCTL_PFINFO_XTAB )
                    continue;

                pagetype &= XEN_DOMCTL_PFINFO_LTABTYPE_MASK;

                if ( (pagetype >= XEN_DOMCTL_PFINFO_L1TAB) &&
                     (pagetype <= XEN_DOMCTL_PFINFO_L4TAB) )
                {
                    /* We have a pagetable page: need to rewrite it. */
                    race = 
                        canonicalize_pagetable(ctx, pagetype, pfn, spage, page); 

                    if ( race && !live )
                    {
                        ERROR("Fatal PT race (pfn %lx, type %08lx)", pfn,
                              pagetype);
                        goto out;
                    }

                    if ( ratewrite(io_fd, live, page, PAGE_SIZE) != PAGE_SIZE )
                    {
                        PERROR("Error when writing to state file (4b)"
                              " (errno %d)", errno);
                        goto out;
                    }
                }
                else
                {
                    /* We have a normal page: accumulate it for writing. */
		    /* Laijs: stop accumulate write temporarily. we will add it back via writev() when needed */
                    if ( ratewrite(io_fd, live, spage, PAGE_SIZE) != PAGE_SIZE )
                    {
                        PERROR("Error when writing to state file (4b)"
                              " (errno %d)", errno);
                        goto out;
                    }
                    run = 0;
                    //run++;
                }
            } /* end of the write out for this batch */

            if ( run )
            {
                /* write out the last accumulated run of pages */
                if ( ratewrite(io_fd, live, 
                               (char*)region_base+(PAGE_SIZE*(j-run)), 
                               PAGE_SIZE*run) != PAGE_SIZE*run )
                {
                    PERROR("Error when writing to state file (4c)"
                          " (errno %d)", errno);
                    goto out;
                }                        
            }

            sent_this_iter += batch;

            //munmap(region_base, batch*PAGE_SIZE);
        } /* end of this while loop for this iteration */

      skip:

        xc_report_progress_step(xch, dinfo->p2m_size, dinfo->p2m_size);

        total_sent += sent_this_iter;

        if ( last_iter )
        {
            print_stats( xch, dom, sent_this_iter, &stats, 1);

            DPRINTF("Total pages sent= %ld (%.2fx)\n",
                    total_sent, ((float)total_sent)/dinfo->p2m_size );
            DPRINTF("(of which %ld were fixups)\n", needed_to_fix  );
        }

        if ( last_iter && debug )
        {
            int id = XC_SAVE_ID_ENABLE_VERIFY_MODE;
            memset(to_send, 0xff, BITMAP_SIZE);
            debug = 0;
            DPRINTF("Entering debug resend-all mode\n");

            /* send "-1" to put receiver into debug mode */
            if ( wrexact(io_fd, &id, sizeof(int)) )
            {
                PERROR("Error when writing to state file (6)");
                goto out;
            }

            continue;
        }

        if ( last_iter )
            break;

        if ( live )
        {
            if ( ((sent_this_iter > sent_last_iter) && RATE_IS_MAX()) ||
                 (iter >= max_iters) ||
                 (sent_this_iter+skip_this_iter < 50) ||
                 (total_sent > dinfo->p2m_size*max_factor) )
            {
                DPRINTF("Start last iteration\n");
                last_iter = 1;

                if ( suspend_and_state(callbacks->suspend, callbacks->data,
                                       xch, io_fd, dom, &info) )
                {
                    ERROR("Domain appears not to have suspended");
                    goto out;
                }
		callbacks->flush_disk(callbacks->data);

                DPRINTF("SUSPEND shinfo %08lx\n", info.shared_info_frame);
                if ( (tmem_saved > 0) &&
                     (xc_tmem_save_extra(xch,dom,io_fd,XC_SAVE_ID_TMEM_EXTRA) == -1) )
                {
                        PERROR("Error when writing to state file (tmem)");
                        goto out;
                }

                if ( save_tsc_info(xch, dom, io_fd) < 0 )
                {
                    PERROR("Error when writing to state file (tsc)");
                    goto out;
                }


            }

            if ( xc_shadow_control(xch, dom,
                                   XEN_DOMCTL_SHADOW_OP_CLEAN, HYPERCALL_BUFFER(to_send),
                                   dinfo->p2m_size, NULL, 0, &stats) != dinfo->p2m_size )
            {
                PERROR("Error flushing shadow PT");
                goto out;
            }

            sent_last_iter = sent_this_iter;

            print_stats(xch, dom, sent_this_iter, &stats, 1);

        }
    } /* end of infinite for loop */

    gettimeofday(&tv, NULL);
    printf("[%lu.%06lu]page transmit end.\n", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec);

    fprintf(stat_fp, "%lu.%06lu\t", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);

    DPRINTF("All memory is saved\n");

    {
        struct {
            int id;
            int max_vcpu_id;
            uint64_t vcpumap;
        } chunk = { XC_SAVE_ID_VCPU_INFO, info.max_vcpu_id };

        if ( info.max_vcpu_id >= 64 )
        {
            ERROR("Too many VCPUS in guest!");
            goto out;
        }

        for ( i = 1; i <= info.max_vcpu_id; i++ )
        {
            xc_vcpuinfo_t vinfo;
            if ( (xc_vcpu_getinfo(xch, dom, i, &vinfo) == 0) &&
                 vinfo.online )
                vcpumap |= 1ULL << i;
        }

        chunk.vcpumap = vcpumap;
        if ( wrexact(io_fd, &chunk, sizeof(chunk)) )
        {
            PERROR("Error when writing to state file");
            goto out;
        }
    }

    if ( hvm )
    {
        struct {
            int id;
            uint32_t pad;
            uint64_t data;
        } chunk = { 0, };

        chunk.id = XC_SAVE_ID_HVM_IDENT_PT;
        chunk.data = 0;
        xc_get_hvm_param(xch, dom, HVM_PARAM_IDENT_PT,
                         (unsigned long *)&chunk.data);

        if ( (chunk.data != 0) &&
             wrexact(io_fd, &chunk, sizeof(chunk)) )
        {
            PERROR("Error when writing the ident_pt for EPT guest");
            goto out;
        }

        chunk.id = XC_SAVE_ID_HVM_VM86_TSS;
        chunk.data = 0;
        xc_get_hvm_param(xch, dom, HVM_PARAM_VM86_TSS,
                         (unsigned long *)&chunk.data);

        if ( (chunk.data != 0) &&
             wrexact(io_fd, &chunk, sizeof(chunk)) )
        {
            PERROR("Error when writing the vm86 TSS for guest");
            goto out;
        }

        chunk.id = XC_SAVE_ID_HVM_CONSOLE_PFN;
        chunk.data = 0;
        xc_get_hvm_param(xch, dom, HVM_PARAM_CONSOLE_PFN,
                         (unsigned long *)&chunk.data);

        if ( (chunk.data != 0) &&
             wrexact(io_fd, &chunk, sizeof(chunk)) )
        {
            PERROR("Error when writing the console pfn for guest");
            goto out;
        }

        chunk.id = XC_SAVE_ID_HVM_ACPI_IOPORTS_LOCATION;
        chunk.data = 0;
        xc_get_hvm_param(xch, dom, HVM_PARAM_ACPI_IOPORTS_LOCATION,
                         (unsigned long *)&chunk.data);

        if ((chunk.data != 0) && wrexact(io_fd, &chunk, sizeof(chunk)))
        {
            PERROR("Error when writing the firmware ioport version");
            goto out;
        }
    }

    //if ( !callbacks->checkpoint )
    //{
        /*
         * If this is not a checkpointed save then this must be the first and
         * last checkpoint.
         */
        i = XC_SAVE_ID_LAST_CHECKPOINT;
        if ( wrexact(io_fd, &i, sizeof(int)) )
        {
            PERROR("Error when writing last checkpoint chunk");
            goto out;
        }
    //}

    /* Zero terminate */
    i = 0;
    if ( wrexact(io_fd, &i, sizeof(int)) )
    {
        PERROR("Error when writing to state file (6')");
        goto out;
    }

    if ( hvm ) 
    {
        uint32_t rec_size;

        /* Save magic-page locations. */
        memset(magic_pfns, 0, sizeof(magic_pfns));
        xc_get_hvm_param(xch, dom, HVM_PARAM_IOREQ_PFN,
                         (unsigned long *)&magic_pfns[0]);
        xc_get_hvm_param(xch, dom, HVM_PARAM_BUFIOREQ_PFN,
                         (unsigned long *)&magic_pfns[1]);
        xc_get_hvm_param(xch, dom, HVM_PARAM_STORE_PFN,
                         (unsigned long *)&magic_pfns[2]);
        if ( wrexact(io_fd, magic_pfns, sizeof(magic_pfns)) )
        {
            PERROR("Error when writing to state file (7)");
            goto out;
        }

        /* Get HVM context from Xen and save it too */
        if ( (rec_size = xc_domain_hvm_getcontext(xch, dom, hvm_buf, 
                                                  hvm_buf_size)) == -1 )
        {
            PERROR("HVM:Could not get hvm buffer");
            goto out;
        }
        
        if ( wrexact(io_fd, &rec_size, sizeof(uint32_t)) )
        {
            PERROR("error write hvm buffer size");
            goto out;
        }
        
        if ( wrexact(io_fd, hvm_buf, rec_size) )
        {
            PERROR("write HVM info failed!");
            goto out;
        }
        
        /* HVM guests are done now */
        rc = 0;
        goto out;
    }

    /* PV guests only from now on */

    /* Send through a list of all the PFNs that were not in map at the close */
    {
        unsigned int i,j;
        unsigned long pfntab[1024];

        for ( i = 0, j = 0; i < dinfo->p2m_size; i++ )
        {
            if ( !is_mapped(pfn_to_mfn(i)) )
                j++;
        }

        if ( wrexact(io_fd, &j, sizeof(unsigned int)) )
        {
            PERROR("Error when writing to state file (6a)");
            goto out;
        }

        for ( i = 0, j = 0; i < dinfo->p2m_size; )
        {
            if ( !is_mapped(pfn_to_mfn(i)) )
                pfntab[j++] = i;

            i++;
            if ( (j == 1024) || (i == dinfo->p2m_size) )
            {
                if ( wrexact(io_fd, &pfntab, sizeof(unsigned long)*j) )
                {
                    PERROR("Error when writing to state file (6b)");
                    goto out;
                }
                j = 0;
            }
        }
    }

    if ( xc_vcpu_getcontext(xch, dom, 0, &ctxt) )
    {
        PERROR("Could not get vcpu context");
        goto out;
    }

    /* Canonicalise the suspend-record frame number. */
    mfn = GET_FIELD(&ctxt, user_regs.edx);
    if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
    {
        ERROR("Suspend record is not in range of pseudophys map");
        goto out;
    }
    SET_FIELD(&ctxt, user_regs.edx, mfn_to_pfn(mfn));

    for ( i = 0; i <= info.max_vcpu_id; i++ )
    {
        if ( !(vcpumap & (1ULL << i)) )
            continue;

        if ( (i != 0) && xc_vcpu_getcontext(xch, dom, i, &ctxt) )
        {
            PERROR("No context for VCPU%d", i);
            goto out;
        }

        /* Canonicalise each GDT frame number. */
        for ( j = 0; (512*j) < GET_FIELD(&ctxt, gdt_ents); j++ )
        {
            mfn = GET_FIELD(&ctxt, gdt_frames[j]);
            if ( !MFN_IS_IN_PSEUDOPHYS_MAP(mfn) )
            {
                ERROR("GDT frame is not in range of pseudophys map");
                goto out;
            }
            SET_FIELD(&ctxt, gdt_frames[j], mfn_to_pfn(mfn));
        }

        /* Canonicalise the page table base pointer. */
        if ( !MFN_IS_IN_PSEUDOPHYS_MAP(UNFOLD_CR3(
                                           GET_FIELD(&ctxt, ctrlreg[3]))) )
        {
            ERROR("PT base is not in range of pseudophys map");
            goto out;
        }
        SET_FIELD(&ctxt, ctrlreg[3], 
            FOLD_CR3(mfn_to_pfn(UNFOLD_CR3(GET_FIELD(&ctxt, ctrlreg[3])))));

        /* Guest pagetable (x86/64) stored in otherwise-unused CR1. */
        if ( (ctx->pt_levels == 4) && ctxt.x64.ctrlreg[1] )
        {
            if ( !MFN_IS_IN_PSEUDOPHYS_MAP(UNFOLD_CR3(ctxt.x64.ctrlreg[1])) )
            {
                ERROR("PT base is not in range of pseudophys map");
                goto out;
            }
            /* Least-significant bit means 'valid PFN'. */
            ctxt.x64.ctrlreg[1] = 1 |
                FOLD_CR3(mfn_to_pfn(UNFOLD_CR3(ctxt.x64.ctrlreg[1])));
        }

        if ( wrexact(io_fd, &ctxt, ((dinfo->guest_width==8) 
                                        ? sizeof(ctxt.x64) 
                                        : sizeof(ctxt.x32))) )
        {
            PERROR("Error when writing to state file (1)");
            goto out;
        }

        domctl.cmd = XEN_DOMCTL_get_ext_vcpucontext;
        domctl.domain = dom;
        domctl.u.ext_vcpucontext.vcpu = i;
        if ( xc_domctl(xch, &domctl) < 0 )
        {
            PERROR("No extended context for VCPU%d", i);
            goto out;
        }
        if ( wrexact(io_fd, &domctl.u.ext_vcpucontext, 128) )
        {
            PERROR("Error when writing to state file (2)");
            goto out;
        }

        /* Start to fetch CPU eXtended States */
        /* Get buffer size first */
        domctl.cmd = XEN_DOMCTL_getvcpuextstate;
        domctl.domain = dom;
        domctl.u.vcpuextstate.vcpu = i;
        domctl.u.vcpuextstate.xfeature_mask = 0;
        domctl.u.vcpuextstate.size = 0;
        if ( xc_domctl(xch, &domctl) < 0 )
        {
            PERROR("No eXtended states (XSAVE) for VCPU%d", i);
            goto out;
        }

        if ( !domctl.u.vcpuextstate.xfeature_mask )
            continue;

        /* Getting eXtended states data */
        buffer = xc_hypercall_buffer_alloc(xch, buffer, domctl.u.vcpuextstate.size);
        if ( !buffer )
        {
            PERROR("Insufficient memory for getting eXtended states for"
                   "VCPU%d", i);
            goto out;
        }
        set_xen_guest_handle(domctl.u.vcpuextstate.buffer, buffer);
        if ( xc_domctl(xch, &domctl) < 0 )
        {
            PERROR("No eXtended states (XSAVE) for VCPU%d", i);
            xc_hypercall_buffer_free(xch, buffer);
            goto out;
        }

        if ( wrexact(io_fd, &domctl.u.vcpuextstate.xfeature_mask,
                     sizeof(domctl.u.vcpuextstate.xfeature_mask)) ||
             wrexact(io_fd, &domctl.u.vcpuextstate.size,
                     sizeof(domctl.u.vcpuextstate.size)) ||
             wrexact(io_fd, buffer, domctl.u.vcpuextstate.size) )
        {
            PERROR("Error when writing to state file VCPU extended state");
            xc_hypercall_buffer_free(xch, buffer);
            goto out;
        }
        xc_hypercall_buffer_free(xch, buffer);
    }

    /*
     * Reset the MFN to be a known-invalid value. See map_frame_list_list().
     */
    memcpy(page, live_shinfo, PAGE_SIZE);
    SET_FIELD(((shared_info_any_t *)page), 
              arch.pfn_to_mfn_frame_list_list, 0);
    if ( wrexact(io_fd, page, PAGE_SIZE) )
    {
        PERROR("Error when writing to state file (1)");
        goto out;
    }

    /* Flush last write and check for errors. */
    if ( fsync(io_fd) && errno != EINVAL )
    {
        PERROR("Error when flushing state file");
        goto out;
    }

    /* Success! */
    rc = 0;

 out:
    completed = 1;
   
    gettimeofday(&tv, NULL); 
    printf("[%lu.%06lu]begin flush sockets.\n", (unsigned long)tv.tv_sec, 
	(unsigned long)tv.tv_usec);
 
    /* Flush last write and discard cache for file. */
    if ( outbuf_flush(xch, &ob, io_fd) < 0 ) {
        PERROR("Error when flushing output buffer");
        rc = 1;
    }

    gettimeofday(&tv, NULL);
    printf("[%lu.%06lu]finished flush, begin discard file cache.\n", (unsigned long)tv.tv_sec,
	(unsigned long)tv.tv_usec);

    discard_file_cache(xch, io_fd, 1);

    gettimeofday(&tv, NULL);
    printf("[%lu.%06lu]finished discard file cache.\n", (unsigned long)tv.tv_sec,
	(unsigned long)tv.tv_usec);


 resume:
    /*
     * master                       slaver
     *                  <----       "finish"
     * flush packets
     * "resume"         ---->
     * resume vm                    resume vm
     */
    read(io_fd, sig_buf, 6);

    if (!first_time)
        /* flush queued packets now */
        ioctl(dev_fd, COMP_IOCTSUSPEND);

    /* notify slaver to resume vm*/
    if (write_exact(io_fd, "resume", 6)) {
        PERROR("write: resume");
        goto out;
    }

    if ( !rc && callbacks->postcopy )
        callbacks->postcopy(callbacks->data);

    if (want_exit)
	goto sigintr;
    
    /* wait VM resume from suspend, and vnif connects */
    //TODO
    gettimeofday(&tv, NULL);
    	frc = syscall(NR_wait_resume);
   
    /* wait slaver finish resume */
    read(io_fd, sig_buf, 7);
    sig_buf[7] = 0;
    gettimeofday(&tv, NULL);
    printf("[%lu.%06lu]Received from slaver: str=%s\n", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec, sig_buf);

    fprintf(stat_fp, "%lu.%06lu\t", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
    /* forward network */
    // COMMENTS: For manually raise ck. 
#ifdef NET_FW
    if(first_time) {
	install_fw_network();
    	start_input_network();
    } else {
	syscall(NR_vif_block, 0);
    }     
#endif

    // COMMENTS: For manually raise ck.
#ifdef NET_FW
    if (!first_time) {
    	// notify compare module checkpoint finish
	gettimeofday(&tv, NULL);
    	printf("[%lu.%06lu]Notify checkpoint finish.\n", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec);
    	ioctl(dev_fd, COMP_IOCTRESUME);
	gettimeofday(&tv, NULL);
    	printf("[%lu.%06lu]Done.\n", (unsigned long)tv.tv_sec,
		(unsigned long)tv.tv_usec);
    }
#endif

    callbacks->checkpoint(callbacks->data);
    
    // COMMENTS: For manually raise ck.
#ifdef NET_FW
    if (first_time) {
	printf("open /dev/HA_compare done.\n");
	dev_fd = open("/dev/HA_compare", O_RDWR);
	if (dev_fd < 0) {
		printf("open /dev/HA_compare failed, check whether load compare module.\n");
		return 1;
	}
    }	
#endif
	/* wait for a new chekcpoint */

start_ck:
    gettimeofday(&tv, NULL);
    printf("[%lu.%06lu]wait for new checkpoint.\n", (unsigned long)tv.tv_sec,
         (unsigned long)tv.tv_usec);

    fprintf(stat_fp, "%lu.%06lu\n", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
#ifdef NET_FW
    if (curr_mode == COMPARE_MODE) {
        while (1) {
            err = ioctl(dev_fd, COMP_IOCTWAIT);
            if (err == 0 || err == -1)
                break;
            if (callbacks->check) {
                err = callbacks->check(callbacks->data);
                if (err)
                    break;
            }
        }
    } else {
        /* buffer mode */
        usleep(interval_us);
    }
#else
		printf("pause:");
		scanf("%d", &err);
#endif
#ifdef FAILOVER
#ifdef NET_FW
	if (err < 0) {
		failover();
		printf("failover.\n");
		scanf("%d", &err);
		goto start_ck;
	}
#endif
#endif

 	gettimeofday(&tv, NULL);
  	printf("[%lu.%06lu]checkpoint start.\n", (unsigned long)tv.tv_sec,
         (unsigned long)tv.tv_usec);

        fprintf(stat_fp, "%lu.%06lu\t", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);

        /* reset stats timer */
        print_stats(xch, dom, 0, &stats, 0);
	
	//stop_input_network();
	syscall(NR_vif_block, 1);
	
	/* notify to continue checkpoint */ 
	if ( write_exact(io_fd, "continue", 8) )
	{
		PERROR("write: continue");
		goto out;
	}

        rc = 1;
        /* last_iter = 1; */
        if ( suspend_and_state(callbacks->suspend, callbacks->data, xch,
                               io_fd, dom, &info) )
        {
            ERROR("Domain appears not to have suspended");
            goto sigintr;
        }
        DPRINTF("SUSPEND shinfo %08lx\n", info.shared_info_frame);
        print_stats(xch, dom, 0, &stats, 1);

        if ( xc_shadow_control(xch, dom,
                               XEN_DOMCTL_SHADOW_OP_CLEAN, HYPERCALL_BUFFER(to_send),
                               dinfo->p2m_size, NULL, 0, &stats) != dinfo->p2m_size )
        {
            PERROR("Error flushing shadow PT");
        }

	/* wait slaver side suspend done */
	while (1) {
		tv.tv_sec = 100;
		tv.tv_usec = 0;

		FD_ZERO(&rfds);
		FD_SET(io_fd, &rfds);
		err = select(io_fd + 1, &rfds, NULL, NULL, &tv);
		if ( err == -1 && errno == EINTR )
			continue;
		if ( !FD_ISSET(io_fd, &rfds) ) {
			printf("Timeout to notify slaver.\n");
			rc = 0;
			want_exit = 1;
                       goto resume;
		}
		
		read(io_fd, sig_buf, 8);
		sig_buf[8] = 0;
 		
                gettimeofday(&tv, NULL);
                printf("[%lu.%06lu]Received from slaver: str=%s\n", (unsigned long)tv.tv_sec,
		      (unsigned long)tv.tv_usec, sig_buf);
  
                fprintf(stat_fp, "%lu.%06lu\t", (unsigned long)tv.tv_sec, (unsigned long)tv.tv_usec);
		break;
        }

	if (sig_buf[0] == 'r')
		goto start_ck;
	
	// Notify the slaver to flush the disk.
 	gettimeofday(&tv, NULL);
	printf("[%lu.%06lu]Begin to flush disk.\n", (unsigned long)tv.tv_sec,
	      (unsigned long)tv.tv_usec);

	callbacks->flush_disk(callbacks->data);
	
	gettimeofday(&tv, NULL);
	printf("[%lu.%06lu]Flush disk end.\n", (unsigned long)tv.tv_sec,
	      (unsigned long)tv.tv_usec);

	write_exact(io_fd, "start", 5);

	/* Tell the xc_domain_restore routine this is not the first checkpoint */
	first_time = 0;
        goto copypages;
    //}
    /* notify to stop checkpoint */
sigintr:
    write_exact(io_fd, "byebye!!", 8);
    close(dev_fd);
    // COMMENTS: For manually raise ck.
    //uninstall_fw_network();

    if ( tmem_saved != 0 && live )
        xc_tmem_save_done(xch, dom);

    if ( live )
    {
        if ( xc_shadow_control(xch, dom, 
                               XEN_DOMCTL_SHADOW_OP_OFF,
                               NULL, 0, NULL, 0, NULL) < 0 )
            DPRINTF("Warning - couldn't disable shadow mode");
        if ( hvm && callbacks->switch_qemu_logdirty(dom, 0, callbacks->data) )
            DPRINTF("Warning - couldn't disable qemu log-dirty mode");
    }

    if ( live_shinfo )
        munmap(live_shinfo, PAGE_SIZE);

    if ( ctx->live_p2m )
        munmap(ctx->live_p2m, P2M_FLL_ENTRIES * PAGE_SIZE);

    if ( ctx->live_m2p )
        munmap(ctx->live_m2p, M2P_SIZE(ctx->max_mfn));

    xc_hypercall_buffer_free_pages(xch, to_send, NRPAGES(BITMAP_SIZE));
    xc_hypercall_buffer_free_pages(xch, to_skip, NRPAGES(BITMAP_SIZE));

    free(pfn_type);
    free(pfn_batch);
    free(pfn_err);
    free(to_fix);
   close(dev_fd);

    DPRINTF("Save exit rc=%d\n",rc);

    fclose(stat_fp);
    return !!rc;
}

int update_colo_mode(int new_mode, int interval_ms)
{
    int rc;

    switch(new_mode)
    {
    case BUFFER_MODE:
        interval_us = interval_ms * 1000;
    case COMPARE_MODE:
        curr_mode = new_mode;
        break;
    default:
        return -EINVAL;
    }

    if (dev_fd < 0)
        return -EBUSY;

    rc = ioctl(dev_fd, COMP_IOCT_SWITCH, new_mode);
    if (rc < 0)
        return -errno;

    return 0;
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
