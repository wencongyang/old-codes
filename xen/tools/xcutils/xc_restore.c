/* 
 * This file is subject to the terms and conditions of the GNU General
 * Public License.  See the file "COPYING" in the main directory of
 * this archive for more details.
 *
 * Copyright (C) 2005 by Christian Limpach
 *
 */

#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>

#include <xenctrl.h>
#include <xenguest.h>
#include <xc_save_restore_colo.h>

int
main(int argc, char **argv)
{
    unsigned int domid, store_evtchn, console_evtchn;
    unsigned int hvm, pae, apic;
    xc_interface *xch;
    int io_fd, ret;
    int superpages;
    unsigned long store_mfn, console_mfn;
    struct restore_callbacks callback, *callback_p;
    int colo = 0;
    char str[10];

    if ( (argc != 8) && (argc != 9) && (argc != 10) )
        errx(1, "usage: %s iofd domid store_evtchn "
             "console_evtchn hvm pae apic [superpages [colo]]", argv[0]);

    xch = xc_interface_open(0,0,0);
    if ( !xch )
        errx(1, "failed to open control interface");

    io_fd = atoi(argv[1]);
    domid = atoi(argv[2]);
    store_evtchn = atoi(argv[3]);
    console_evtchn = atoi(argv[4]);
    hvm  = atoi(argv[5]);
    pae  = atoi(argv[6]);
    apic = atoi(argv[7]);
    if ( argc == 9 )
        superpages = atoi(argv[8]);
    else
        superpages = 0;

    if ( argc == 10 )
        colo = atoi(argv[9]);

    scanf("%s", str);
    scanf("%s", str);
    scanf("%s", str);

    if ( colo )
    {
        callback.init = restore_colo_init;
        callback.free = restore_colo_free;
        callback.get_page = get_page;
        callback.flush_memory = flush_memory;
        callback.update_p2m = update_p2m_table;
        callback.finish_restotre = finish_colo;
        callback.data = NULL;
        callback_p = &callback;
    }
    else
    {
        callback_p = NULL;
    }

    ret = xc_domain_restore(xch, io_fd, domid, store_evtchn, &store_mfn,
                            console_evtchn, &console_mfn, hvm, pae, superpages,
                            callback_p);

    if ( ret == 0 )
    {
        printf("store-mfn %li\n", store_mfn);
        if ( !hvm )
            printf("console-mfn %li\n", console_mfn);
        fflush(stdout);
    }

    xc_interface_close(xch);

    return ret;
}
