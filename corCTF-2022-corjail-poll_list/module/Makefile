# at first type on ur terminal that $(uname -r) then u will get the version..
# that is using on ur system
 
obj-m += cormon.o

#KDIR = /usr/src/linux-headers-$(shell uname -r)
KDIR =/home/john/Desktop/tmp/test/linux-5.10.127
PWD = $(shell pwd)
CC=gcc
 
all:
	$(MAKE) -C $(KDIR) M=$(shell pwd) modules
 
clean:
	rm -rf *.o *~ core .depend .*.cmd *.ko *.mod.c .tmp_versions
