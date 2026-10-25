obj-m += rqs-scanner.o
KBUILD_CFLAGS += -DDEBUG=1

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
