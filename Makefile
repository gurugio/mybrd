obj-m := mybrd.o
KERN_SOURCE := /lib/modules/$(shell uname -r)/build

default:
		$(MAKE) -C $(KERN_SOURCE) M=$(PWD) modules
clean:
		$(MAKE) -C $(KERN_SOURCE) M=$(PWD) clean
