obj-m := smoke_bomb.o

smoke_bomb-y += sb_lkm.o
smoke_bomb-y += addr.o
smoke_bomb-y += ../arm/patch.o
smoke_bomb-y += ../arm/insn.o

KDIR   := /usr/include/kernel_header/debug
-include $(KDIR)/off_tree_module_build.mk

PWD    := $(shell pwd)

# flags
ifeq ($(CHIP_NAME), HAWKM)
ccflags-y += -mcpu=cortex-a15
else ifeq ($(CHIP_NAME), HAWKP)
ccflags-y += -mcpu=cortex-a15
endif

ccflags-y += -D_SMOKE_BOMB_LKM
ccflags-y += -D_SMOKE_BOMB_ARMV7
#ccflags-y += -D_SMOKE_BOMB_DEBUG


default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

