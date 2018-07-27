obj-m += nfhook.o
obj-m += test_hook.o

KVER ?= $(shell uname -r)

all:
	$(MAKE) -C /lib/modules/$(KVER)/build M=$(PWD) modules

clean:
	$(MAKE) -C /lib/modules/$(KVER)/build M=$(PWD) clean

