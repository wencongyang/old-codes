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
#include <string.h>

#include <xenctrl.h>
#include <xenguest.h>

int
main(int argc, char **argv)
{
    unsigned int domid, store_evtchn, console_evtchn;
    unsigned int hvm, pae, apic;
    xc_interface *xch;
    int io_fd, ret;
    int superpages;
    unsigned long store_mfn, console_mfn;
    char str[10];

    if ( (argc != 8) && (argc != 9) )
        errx(1, "usage: %s iofd domid store_evtchn "
             "console_evtchn hvm pae apic [superpages]", argv[0]);

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

	scanf("%s", str);
	
	if ( !strcmp(str, "EOF") ) return 0;
	// start
	scanf("%s", str);
	store_evtchn = atoi(str);
	scanf("%s", str);
	console_evtchn = atoi(str);

    ret = xc_domain_restore(xch, io_fd, domid, store_evtchn, &store_mfn,
                            console_evtchn, &console_mfn, hvm, pae, superpages);

   	 if ( ret == 0 )
    	 {
		fflush(stdout);
    	} else {
		printf("error\n");
		fflush(stdout);
	}

    xc_interface_close(xch);

    return ret;
}
