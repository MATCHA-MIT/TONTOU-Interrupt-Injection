obj-m += kprobe_logger.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD  := $(shell pwd)
MOD  := kprobe_logger
KO   := $(MOD).ko

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# "install" = build + load module immediately
install: all
	@echo "Loading $(KO) (will prompt for sudo)..."
	sudo insmod $(KO)

# Convenience targets
uninstall:
	@echo "Unloading $(MOD) (will prompt for sudo)..."
	sudo rmmod $(MOD) || true