obj-m += StringIPC.o
StringIPC-objs := main.o

KERNELDR:=/home/john/Desktop/stringIPC/linux-4.4.184
PWD := $(shell pwd) 

modules:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules  
moduels_install:  
	$(MAKE) -C $(KERNELDR) M=$(PWD) modules_install  
clean:  
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions