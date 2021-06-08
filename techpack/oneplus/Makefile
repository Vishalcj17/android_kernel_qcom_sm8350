# SPDX-License-Identifier: GPL-2.0

include $(srctree)/techpack/oneplus/config/oneplus.conf

LINUXINCLUDE	+= -include $(srctree)/techpack/oneplus/config/oneplus.h
LINUXINCLUDE	+= -I$(srctree)/techpack/oneplus/include
USERINCLUDE	+= -I$(srctree)/techpack/oneplus/include

ifeq ($(CONFIG_QGKI),y)
include $(srctree)/techpack/oneplus/config/coretech.conf
LINUXINCLUDE	+= -include $(srctree)/techpack/oneplus/config/coretech.h
endif

obj-y					+= input/
obj-y					+= misc/
obj-$(CONFIG_OPLUS_SM8350_CHARGER)	+= power/
obj-$(CONFIG_TRI_STATE_KEY)		+= tri_state_key/
obj-$(CONFIG_AW8697_HAPTIC)		+= vibrator/
