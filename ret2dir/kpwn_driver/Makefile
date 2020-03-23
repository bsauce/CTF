# at first type on ur terminal that $(uname -r) then u will get the version..
# that is using on ur system
 
obj-m += kpwn.o

#KDIR =/usr/src/linux-headers-$(shell uname -r)
KDIR = /home/john/Desktop/kernel/linux-5.0
 
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
 
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions