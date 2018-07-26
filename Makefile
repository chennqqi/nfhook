nfhook-objs = nfhook_hook.o
obj-m += nfhook.o

#test_hook-objs = test_hook.o
obj-m += test_hook.o

KVER ?= $(shell uname -r)

all:
	$(MAKE) -C /lib/modules/$(KVER)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVER)/build M=$(PWD) clean

