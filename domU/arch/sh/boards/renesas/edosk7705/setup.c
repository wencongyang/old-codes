/*
 * arch/sh/boards/renesas/edosk7705/setup.c
 *
 * Copyright (C) 2000  Kazumoto Kojima
 *
 * Hitachi SolutionEngine Support.
 *
 * Modified for edosk7705 development
 * board by S. Dunn, 2003.
 */

#include <linux/init.h>
#include <asm/machvec.h>
#include <asm/machvec_init.h>
#include <asm/edosk7705/io.h>

static void init_edosk7705(void);

/*
 * The Machine Vector
 */

struct sh_machine_vector mv_edosk7705 __initmv = {
	.mv_nr_irqs		= 80,

	.mv_inb			= sh_edosk7705_inb,
	.mv_inl			= sh_edosk7705_inl,
	.mv_outb		= sh_edosk7705_outb,
	.mv_outl		= sh_edosk7705_outl,

	.mv_inl_p		= sh_edosk7705_inl,
	.mv_outl_p		= sh_edosk7705_outl,

	.mv_insb		= sh_edosk7705_insb,
	.mv_insl		= sh_edosk7705_insl,
	.mv_outsb		= sh_edosk7705_outsb,
	.mv_outsl		= sh_edosk7705_outsl,

	.mv_isa_port2addr	= sh_edosk7705_isa_port2addr,
	.mv_init_irq		= init_edosk7705,
};
ALIAS_MV(edosk7705)

static void __init init_edosk7705(void)
{
	/* This is the Ethernet interrupt */
	make_imask_irq(0x09);
}

const char *get_system_type(void)
{
	return "EDOSK7705";
}

void __init platform_setup(void)
{
	/* Nothing .. */
}

