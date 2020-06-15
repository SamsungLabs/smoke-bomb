obj-m := cache.o

cache-y += cache_test.o
cache-y += lru_test.o
cache-y += line_fill_test.o
cache-y += icache_test.o

KDIR   := /usr/include/kernel_header/debug
-include $(KDIR)/off_tree_module_build.mk

PWD    := $(shell pwd)

# flags
ifeq ($(CHIP_NAME), HAWKM)
ccflags-y += -mcpu=cortex-a15
else ifeq ($(CHIP_NAME), HAWKP)
ccflags-y += -mcpu=cortex-a15
endif

#ccflags-y += -O0

default:
	make -C $(KDIR) M=$(PWD) modules

clean:
	make -C $(KDIR) M=$(PWD) clean

