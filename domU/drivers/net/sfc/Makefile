
sfc-y			+= efx.o nic.o falcon.o siena.o tx.o rx.o \
			   falcon_gmac.o falcon_xmac.o mcdi_mac.o selftest.o \
			   driverlink.o ethtool.o qt202x_phy.o mdio_10g.o \
			   tenxpress.o falcon_boards.o mcdi.o linux_mdio.o \
			   mcdi_phy.o ioctl.o kernel_compat.o lm87.o lm90.o
sfc-$(CONFIG_SFC_MTD)	+= mtd.o
sfc-$(CONFIG_SFC_DEBUGFS) += debugfs.o

obj-$(CONFIG_SFC)	+= sfc.o

obj-$(CONFIG_SFC_RESOURCE) += sfc_resource/

EXTRA_CFLAGS += -DEFX_USE_KCOMPAT=1 -Wno-unused-label
