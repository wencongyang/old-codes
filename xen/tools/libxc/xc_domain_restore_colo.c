#include <xc_save_restore_colo.h>
#include <xs.h>

#define NR_wait_resume 312

struct restore_colo_data
{
    unsigned long max_mem_pfn;

    /* cache the whole memory */
    char* pagebase;

    /* which page is dirty? */
    unsigned long *dirty_pages;

    /* suspend evtchn */
    int local_port;

    xc_evtchn *xce;

    int first_time;

    /* PV */
    /* store the pfn type on slave side */
    unsigned long *pfn_type_slaver;

    /* temp buffer(avoid malloc/free frequently) */
    unsigned long *pfn_batch_slaver;
    unsigned long *pfn_type_batch_slaver;
    unsigned long *p2m_frame_list_temp;

    /* HVM */
    int *pfn_err;
    char *vm_mm;
    struct xs_handle *xsh;
};

/* we restore only one vm in a process, so it is same to use global variable */
DECLARE_HYPERCALL_BUFFER(unsigned long, dirty_pages);

int restore_colo_init(struct restore_data *comm_data, void **data)
{
    xc_dominfo_t info;
    int i;
    unsigned long size;
    xc_interface *xch = comm_data->xch;
    struct restore_colo_data *colo_data;
    struct domain_info_context *dinfo = comm_data->dinfo;
    DECLARE_HYPERCALL;

    if (dirty_pages)
        /* restore_colo_init() is called more than once?? */
        return -1;

    colo_data = calloc(1, sizeof(struct restore_colo_data));
    if (!colo_data)
        return -1;

    if (comm_data->hvm)
        goto hvm;

    if (xc_domain_getinfo(xch, comm_data->dom, 1, &info) != 1)
    {
        PERROR("Could not get domain info");
        goto err;
    }

    colo_data->max_mem_pfn = info.max_memkb >> (PAGE_SHIFT - 10);

    colo_data->pfn_type_slaver = calloc(dinfo->p2m_size, sizeof(xen_pfn_t));
    colo_data->pfn_batch_slaver = calloc(MAX_BATCH_SIZE, sizeof(xen_pfn_t));
    colo_data->pfn_type_batch_slaver = calloc(MAX_BATCH_SIZE, sizeof(xen_pfn_t));
    colo_data->p2m_frame_list_temp = malloc(P2M_FL_ENTRIES);
    if (!colo_data->pfn_type_slaver || !colo_data->pfn_batch_slaver ||
        !colo_data->pfn_type_batch_slaver || !colo_data->p2m_frame_list_temp) {
        PERROR("Could not allocate memory for restore colo data");
        goto err;
    }

    goto skip_hvm;

hvm:
    colo_data->max_mem_pfn = dinfo->p2m_size;
    colo_data->pfn_err = calloc(dinfo->p2m_size, sizeof(int));
    if (!colo_data->pfn_err) {
        PERROR("Could not allocate memory for restore colo data");
        goto err;
    }

    colo_data->xsh = xs_daemon_open();
    if (!colo_data->xsh) {
        PERROR("Cound not open xs daemon");
        goto err;
    }

skip_hvm:
    dirty_pages = xc_hypercall_buffer_alloc_pages(xch, dirty_pages, NRPAGES(BITMAP_SIZE));
    colo_data->dirty_pages = dirty_pages;

    size = dinfo->p2m_size * PAGE_SIZE;
    colo_data->pagebase = malloc(size);
    if (!colo_data->dirty_pages || !colo_data->pagebase) {
        PERROR("Could not allocate memory for restore colo data");
        goto err;
    }

    colo_data->xce = xc_evtchn_open(NULL, 0);
    if (!colo_data->xce) {
        PERROR("Could not open evtchn");
        goto err;
    }

    for (i = 0; i < dinfo->p2m_size; i++)
        comm_data->pfn_type[i] = XEN_DOMCTL_PFINFO_XTAB;
    memset(dirty_pages, 0xff, BITMAP_SIZE);
    colo_data->first_time = 1;
    colo_data->local_port = -1;
    *data = colo_data;

    /* set which side */
    hypercall.op = __HYPERVISOR_which_side_op;
    hypercall.arg[0] = (unsigned long)comm_data->dom;
    do_xen_hypercall(xch, &hypercall);

    return 0;

err:
    restore_colo_free(comm_data, colo_data);
    *data = NULL;
    return -1;
}

void restore_colo_free(struct restore_data *comm_data, void *data)
{
    struct restore_colo_data *colo_data = data;
    struct domain_info_context *dinfo = comm_data->dinfo;

    if (!colo_data)
        return;

    free(colo_data->pfn_type_slaver);
    free(colo_data->pagebase);
    free(colo_data->pfn_batch_slaver);
    free(colo_data->pfn_type_batch_slaver);
    free(colo_data->p2m_frame_list_temp);
    if (dirty_pages)
        xc_hypercall_buffer_free_pages(comm_data->xch, dirty_pages,
                                       NRPAGES(BITMAP_SIZE));
    if (colo_data->xce)
        xc_evtchn_close(colo_data->xce);
    free(colo_data);
}

char* get_page(struct restore_data *comm_data, void *data,
               unsigned long pfn)
{
    struct restore_colo_data *colo_data = data;

    set_bit(pfn, colo_data->dirty_pages);
    return colo_data->pagebase + pfn * PAGE_SIZE;
}

/* Step1: pin non-dirty L1 pagetables: ~dirty_pages & mL1 (= ~dirty_pages & sL1) */
static int pin_l1(struct restore_data *comm_data,
                  struct restore_colo_data *colo_data)
{
    unsigned int nr_pins = 0;
    unsigned long i;
    struct mmuext_op pin[MAX_PIN_BATCH];
    struct domain_info_context *dinfo = comm_data->dinfo;
    unsigned long *pfn_type = comm_data->pfn_type;
    uint32_t dom = comm_data->dom;
    xc_interface *xch = comm_data->xch;
    unsigned long *pfn_type_slaver = colo_data->pfn_type_slaver;
    unsigned long *dirty_pages = colo_data->dirty_pages;

    for (i = 0; i < dinfo->p2m_size; i++)
    {
        switch ( pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            if (pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LPINTAB)
                /* don't pin already pined */
                continue;

            if (test_bit(i, dirty_pages))
                /* don't pin dirty */
                continue;

            /* here, it must also be L1 in slaver, otherwise it is dirty.
             * (add test code ?)
             */
            pin[nr_pins].cmd = MMUEXT_PIN_L1_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L4TAB:
        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = comm_data->p2m[i];
        nr_pins++;

        /* Batch full? Then flush. */
        if (nr_pins == MAX_PIN_BATCH)
        {
            if (xc_mmuext_op(xch, pin, nr_pins, dom) < 0)
            {
                PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
                return 1;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ((nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0))
    {
        PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
        return 1;
    }

    return 0;
}

/* Step2: unpin pagetables execpt non-dirty L1: sL2 + sL3 + sL4 + (dirty_pages & sL1) */
static int unpin_pagetable(struct restore_data *comm_data,
                           struct restore_colo_data *colo_data)
{
    unsigned int nr_pins = 0;
    unsigned long i;
    struct mmuext_op pin[MAX_PIN_BATCH];
    struct domain_info_context *dinfo = comm_data->dinfo;
    uint32_t dom = comm_data->dom;
    xc_interface *xch = comm_data->xch;
    unsigned long *pfn_type_slaver = colo_data->pfn_type_slaver;
    unsigned long *dirty_pages = colo_data->dirty_pages;

    for (i = 0; i < dinfo->p2m_size; i++)
    {
        if ( (pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LPINTAB) == 0 )
            continue;

        switch ( pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            if (!test_bit(i, dirty_pages)) // it is in (~dirty_pages & mL1), keep it
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

        pin[nr_pins].arg1.mfn = comm_data->p2m[i];
        nr_pins++;

        /* Batch full? Then flush. */
        if (nr_pins == MAX_PIN_BATCH)
        {
            if (xc_mmuext_op(xch, pin, nr_pins, dom) < 0)
            {
                PERROR("Failed to unpin batch of %d page tables", nr_pins);
                return 1;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ((nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0))
    {
        PERROR("Failed to unpin batch of %d page tables", nr_pins);
        return 1;
    }

    return 0;
}

/* we have unpined all pagetables except non-diry l1. So it is OK to map the dirty memory
 * and update it.
 */
static int update_memory(struct restore_data *comm_data,
                         struct restore_colo_data *colo_data)
{
    unsigned long pfn;
    unsigned long max_mem_pfn = colo_data->max_mem_pfn;
    unsigned long *pfn_type = comm_data->pfn_type;
    unsigned long pagetype;
    uint32_t dom = comm_data->dom;
    xc_interface *xch = comm_data->xch;
    int hvm = comm_data->hvm;
    struct xc_mmu *mmu = comm_data->mmu;
    struct domain_info_context *dinfo = comm_data->dinfo;
    unsigned long *dirty_pages = colo_data->dirty_pages;
    char *pagebase = colo_data->pagebase;
    int pfn_err = 0;
    char *region_base_slaver;
    xen_pfn_t region_mfn_slaver;
    unsigned long mfn;
    char *pagebuff;

    if (hvm && !colo_data->vm_mm) {
        unsigned long *pfn_type = calloc(dinfo->p2m_size,
                                         sizeof(unsigned long));
        unsigned long k;

        for (k = 0; k < dinfo->p2m_size; k++)
            pfn_type[k] = k;

        colo_data->vm_mm = xc_map_foreign_bulk(xch, dom, PROT_WRITE,
                                               pfn_type,
                                               colo_data->pfn_err,
                                               dinfo->p2m_size);
        if (!colo_data->vm_mm) {
            PERROR("can't map vm total memory");
            return 1;
        }
    }

    for (pfn = 0; pfn < max_mem_pfn; pfn++) {
        if (!test_bit(pfn, dirty_pages))
            continue;

        pagetype = pfn_type[pfn] & XEN_DOMCTL_PFINFO_LTAB_MASK;
        if (pagetype == XEN_DOMCTL_PFINFO_XTAB)
            /* a bogus/unmapped page: skip it */
            continue;

        mfn = comm_data->p2m[pfn];
        region_mfn_slaver = mfn;
        if (hvm) {
            if (colo_data->pfn_err[pfn]) {
                ERROR("update_memory: xc_map_foreign_bulk failed");
                return 1;
            }
            region_base_slaver = colo_data->vm_mm + pfn * PAGE_SIZE;
        } else {
            region_base_slaver = xc_map_foreign_bulk(xch, dom,
                                                     PROT_WRITE,
                                                     &region_mfn_slaver,
                                                     &pfn_err, 1);
            if (!region_base_slaver || pfn_err) {
                PERROR("update_memory: xc_map_foreign_bulk failed");
                return 1;
            }
        }

        pagebuff = (char *)(pagebase + pfn * PAGE_SIZE);
        memcpy(region_base_slaver, pagebuff, PAGE_SIZE);
        if (!hvm)
            munmap(region_base_slaver, PAGE_SIZE);

        if (!hvm &&
            xc_add_mmu_update(xch, mmu,
                (((unsigned long long)mfn) << PAGE_SHIFT)
                | MMU_MACHPHYS_UPDATE, pfn) )
        {
            PERROR("failed machpys update mfn=%lx pfn=%lx", mfn, pfn);
            return 1;
        }
    }

    /*
     * Ensure we flush all machphys updates before potential PAE-specific
     * reallocations below.
     */
    if (!hvm && xc_flush_mmu_updates(xch, mmu))
    {
        PERROR("Error doing flush_mmu_updates()");
        return 1;
    }

    return 0;
}

/* Step 4: pin master pt
 * Pin page tables. Do this after writing to them as otherwise Xen
 * will barf when doing the type-checking.
 */
static int pin_pagetable(struct restore_data *comm_data,
                         struct restore_colo_data *colo_data)
{
    unsigned int nr_pins = 0;
    unsigned long i;
    struct mmuext_op pin[MAX_PIN_BATCH];
    struct domain_info_context *dinfo = comm_data->dinfo;
    unsigned long *pfn_type = comm_data->pfn_type;
    uint32_t dom = comm_data->dom;
    xc_interface *xch = comm_data->xch;
    unsigned long *dirty_pages = colo_data->dirty_pages;

    for ( i = 0; i < dinfo->p2m_size; i++ )
    {
        if ( (pfn_type[i] & XEN_DOMCTL_PFINFO_LPINTAB) == 0 )
            continue;

        switch ( pfn_type[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            if (!test_bit(i, dirty_pages))
                /* it is in (~dirty_pages & mL1)(=~dirty_pages & sL1),
                 * already pined
                 */
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

        pin[nr_pins].arg1.mfn = comm_data->p2m[i];
        nr_pins++;

        /* Batch full? Then flush. */
        if (nr_pins == MAX_PIN_BATCH)
        {
            if (xc_mmuext_op(xch, pin, nr_pins, dom) < 0)
            {
                PERROR("Failed to pin batch of %d page tables", nr_pins);
                return 1;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ((nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0))
    {
        PERROR("Failed to pin batch of %d page tables", nr_pins);
        return 1;
    }

    return 0;
}

/* Step5: unpin unneeded non-dirty L1 pagetables: ~dirty_pages & mL1 (= ~dirty_pages & sL1) */
static int unpin_l1(struct restore_data *comm_data,
                    struct restore_colo_data *colo_data)
{
    unsigned int nr_pins = 0;
    unsigned long i;
    struct mmuext_op pin[MAX_PIN_BATCH];
    struct domain_info_context *dinfo = comm_data->dinfo;
    unsigned long *pfn_type = comm_data->pfn_type;
    uint32_t dom = comm_data->dom;
    xc_interface *xch = comm_data->xch;
    unsigned long *pfn_type_slaver = colo_data->pfn_type_slaver;
    unsigned long *dirty_pages = colo_data->dirty_pages;

    for (i = 0; i < dinfo->p2m_size; i++)
    {
        switch ( pfn_type_slaver[i] & XEN_DOMCTL_PFINFO_LTABTYPE_MASK )
        {
        case XEN_DOMCTL_PFINFO_L1TAB:
            if (pfn_type[i] & XEN_DOMCTL_PFINFO_LPINTAB) // still needed
                continue;
            if (test_bit(i, dirty_pages)) // not pined by step 1
                continue;

            pin[nr_pins].cmd = MMUEXT_UNPIN_TABLE;
            break;

        case XEN_DOMCTL_PFINFO_L2TAB:
        case XEN_DOMCTL_PFINFO_L3TAB:
        case XEN_DOMCTL_PFINFO_L4TAB:
        default:
            continue;
        }

        pin[nr_pins].arg1.mfn = comm_data->p2m[i];
        nr_pins++;

        /* Batch full? Then flush. */
        if (nr_pins == MAX_PIN_BATCH)
        {
            if (xc_mmuext_op(xch, pin, nr_pins, dom) < 0)
            {
                PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
                return 1;
            }
            nr_pins = 0;
        }
    }

    /* Flush final partial batch. */
    if ((nr_pins != 0) && (xc_mmuext_op(xch, pin, nr_pins, dom) < 0))
    {
        PERROR("Failed to pin L1 batch of %d page tables", nr_pins);
        return 1;
    }

    return 0;
}

int flush_memory(struct restore_data *comm_data, void *data)
{
    struct restore_colo_data *colo_data = data;

    if (!comm_data->hvm) {
        if (pin_l1(comm_data, colo_data) != 0)
            return -1;
        if (unpin_pagetable(comm_data, colo_data) != 0)
            return -1;
    }
    if (update_memory(comm_data, colo_data) != 0)
        return -1;
    if (!comm_data->hvm) {
        if (pin_pagetable(comm_data, colo_data) != 0)
            return -1;
        if (unpin_l1(comm_data, colo_data) != 0)
            return -1;

        memcpy(colo_data->pfn_type_slaver, comm_data->pfn_type,
               comm_data->dinfo->p2m_size * sizeof(xen_pfn_t));
    }

    return 0;
}

int update_p2m_table(struct restore_data *comm_data, void *data)
{
    struct restore_colo_data *colo_data = data;
    unsigned long i, j, n, pfn;
    unsigned long *p2m_frame_list = comm_data->p2m_frame_list;
    struct domain_info_context *dinfo = comm_data->dinfo;
    unsigned long *pfn_type = comm_data->pfn_type;
    xc_interface *xch = comm_data->xch;
    uint32_t dom = comm_data->dom;
    unsigned long *dirty_pages = colo_data->dirty_pages;
    unsigned long *p2m_frame_list_temp = colo_data->p2m_frame_list_temp;

    /* A temporay mapping of the guest's p2m table(all dirty pages) */
    xen_pfn_t *live_p2m;
    /* A temporay mapping of the guest's p2m table(1 page) */
    xen_pfn_t *live_p2m_one;
    unsigned long *p2m;

    j = 0;
    for (i = 0; i < P2M_FL_ENTRIES; i++)
    {
        pfn = p2m_frame_list[i];
        if ((pfn >= dinfo->p2m_size) || (pfn_type[pfn] != XEN_DOMCTL_PFINFO_NOTAB))
        {
            ERROR("PFN-to-MFN frame number %i (%#lx) is bad", i, pfn);
            return -1;
        }

        if (!test_bit(pfn, dirty_pages))
            continue;

        p2m_frame_list_temp[j++] = comm_data->p2m[pfn];
    }

    if (j)
    {
        /* Copy the P2M we've constructed to the 'live' P2M */
        if (!(live_p2m = xc_map_foreign_pages(xch, dom, PROT_WRITE,
                                              p2m_frame_list_temp, j)))
        {
            PERROR("Couldn't map p2m table");
            return -1;
        }

        j = 0;
        for (i = 0; i < P2M_FL_ENTRIES; i++)
        {
            pfn = p2m_frame_list[i];
            if (!test_bit(pfn, dirty_pages))
                continue;

            live_p2m_one = (xen_pfn_t *)((char *)live_p2m + PAGE_SIZE * j++);
            /* If the domain we're restoring has a different word size to ours,
             * we need to adjust the live_p2m assignment appropriately */
            if (dinfo->guest_width > sizeof (xen_pfn_t))
            {
                n = (i + 1) * FPP - 1;
                for (i = FPP - 1; i >= 0; i--)
                    ((uint64_t *)live_p2m_one)[i] = (long)comm_data->p2m[n--];
            }
            else if (dinfo->guest_width < sizeof (xen_pfn_t))
            {
                n = i * FPP;
                for (i = 0; i < FPP; i++)
                    ((uint32_t *)live_p2m_one)[i] = comm_data->p2m[n++];
            }
            else
            {
                p2m = (xen_pfn_t *)((char *)comm_data->p2m + PAGE_SIZE * i);
                memcpy(live_p2m_one, p2m, PAGE_SIZE);
            }
        }
        munmap(live_p2m, j * PAGE_SIZE);
    }

    return 0;
}

static int update_pfn_type(xc_interface *xch, uint32_t dom, int count, xen_pfn_t *pfn_batch,
   xen_pfn_t *pfn_type_batch, xen_pfn_t *pfn_type)
{
    unsigned long k;

    if (xc_get_pfn_type_batch(xch, dom, count, pfn_type_batch))
    {
        ERROR("xc_get_pfn_type_batch for slaver failed");
        return -1;
    }

    for (k = 0; k < count; k++)
        pfn_type[pfn_batch[k]] = pfn_type_batch[k] & XEN_DOMCTL_PFINFO_LTAB_MASK;

    return 0;
}

/* we are ready to start the guest when this functions is called. We
 * will return until we need to do a new checkpoint or some error occurs.
 *
 * communication with python
 * python code                  restore code        comment
 *                  <====       "finish\n"
 * "resume\n"       ====>                           guest is resumed
 *                  <====       "resume\n"          postresume is done
 * "suspend\n"      ====>                           a new checkpoint begins
 *                  <====       "suspend\n"         guest is suspended
 * "start\n"        ====>                           getting dirty pages begins
 *
 * return value:
 * -1: error
 *  0: continue to start vm
 *  1: continue to do a checkpoint
 */
int finish_colo(struct restore_data *comm_data, void *data)
{
    struct restore_colo_data *colo_data = data;
    xc_interface *xch = comm_data->xch;
    uint32_t dom = comm_data->dom;
    struct domain_info_context *dinfo = comm_data->dinfo;
    xc_evtchn *xce = colo_data->xce;
    unsigned long *pfn_batch_slaver = colo_data->pfn_batch_slaver;
    unsigned long *pfn_type_batch_slaver = colo_data->pfn_type_batch_slaver;
    unsigned long *pfn_type_slaver = colo_data->pfn_type_slaver;
    struct xs_handle *xsh = colo_data->xsh;
    DECLARE_HYPERCALL;

    unsigned long i, j;
    int rc;
    char str[10];
    int remote_port;
    int local_port = colo_data->local_port;

    /* output the store-mfn & console-mfn */
    printf("store-mfn %li\n", comm_data->store_mfn);
    printf("console-mfn %li\n", comm_data->console_mfn);

    /* we need to know which pages are dirty to restore the guest */
    if (xc_shadow_control(xch, dom, XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY, NULL,
                          0, NULL, 0, NULL) < 0 )
    {
        rc = xc_shadow_control(xch, dom, XEN_DOMCTL_SHADOW_OP_OFF, NULL, 0,
                               NULL, 0, NULL);
        if (rc >= 0)
        {
            rc = xc_shadow_control(xch, dom,
                                   XEN_DOMCTL_SHADOW_OP_ENABLE_LOGDIRTY, NULL,
                                   0, NULL, 0, NULL);
        }
        if (rc < 0)
        {
            ERROR("enabling logdirty fails");
            return -1;
        }
    }

    /* notify python code checkpoint finish */
    printf("finish\n");
    fflush(stdout);

    /* wait domain resume, then connect the suspend evtchn */
    scanf("%s", str);
    if (strcmp(str, "resume"))
    {
        ERROR("read %s, expect resume", str);
        return -1;
    }

    while(1) {
        rc = syscall(NR_wait_resume);
        if (rc == 0)
            break;
    }

    /* notify python code vm is resumed */
    printf("resume\n");
    fflush(stdout);

    if (colo_data->first_time) {
        sleep(10);
        remote_port = xs_suspend_evtchn_port(dom);
        if (remote_port < 0) {
            ERROR("getting remote suspend port fails");
            return -1;
        }

        local_port = xc_suspend_evtchn_init(xch, xce, dom, remote_port);
        if (local_port < 0) {
            ERROR("initializing suspend evtchn fails");
            return -1;
        }

        colo_data->local_port = local_port;
    }

    /* wait for the next checkpoint */
    scanf("%s", str);
    if (strcmp(str, "suspend"))
    {
        ERROR("wait for a new checkpoint fails");
        /* start the guest now? */
        return 0;
    }

    /* notify the suspend evtchn */
    rc = xc_evtchn_notify(xce, local_port);
    if (rc < 0)
    {
        ERROR("notifying the suspend evtchn fails");
        return -1;
    }

    rc = xc_await_suspend(xch, xce, local_port);
    if (rc < 0)
    {
        ERROR("waiting suspend fails");
        return -1;
    }

    if (comm_data->hvm && xc_suspend_qemu(xch, xsh, dom) < 0) {
        ERROR("suspending qemu fails");
        return -1;
    }

    /* notify python code suspend is done */
    printf("suspend\n");
    fflush(stdout);

    scanf("%s", str);

    if (strcmp(str, "start"))
        return -1;

    scanf("%s", str);
    scanf("%s", str);

    memset(colo_data->dirty_pages, 0x0, BITMAP_SIZE);
    if (xc_shadow_control(xch, dom, XEN_DOMCTL_SHADOW_OP_CLEAN,
                          HYPERCALL_BUFFER(dirty_pages), dinfo->p2m_size,
                          NULL, 0, NULL) != dinfo->p2m_size)
    {
        ERROR("getting slaver dirty fails");
        return -1;
    }

    if (xc_shadow_control(xch, dom, XEN_DOMCTL_SHADOW_OP_OFF, NULL, 0, NULL,
                          0, NULL) < 0 )
    {
        ERROR("disabling dirty-log fails");
        return -1;
    }

    if (comm_data->hvm) {
        colo_data->first_time = 0;
        return 1;
    }

    j = 0;
    for (i = 0; i < colo_data->max_mem_pfn; i++)
    {
        if ( !test_bit(i, colo_data->dirty_pages) )
            continue;

        pfn_batch_slaver[j] = i;
        pfn_type_batch_slaver[j++] = comm_data->p2m[i];
        if (j == MAX_BATCH_SIZE)
        {
            if (update_pfn_type(xch, dom, j, pfn_batch_slaver,
                                pfn_type_batch_slaver, pfn_type_slaver))
            {
                return -1;
            }
            j = 0;
        }
    }

    if (j)
    {
        if (update_pfn_type(xch, dom, j, pfn_batch_slaver,
                            pfn_type_batch_slaver, pfn_type_slaver))
        {
            return -1;
        }
    }

    /* reset memory */
    hypercall.op = __HYPERVISOR_reset_vcpu_op;
    hypercall.arg[0] = (unsigned long)dom;
    do_xen_hypercall(xch, &hypercall);

    colo_data->first_time = 0;

    return 1;
}
