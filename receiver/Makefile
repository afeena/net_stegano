# Environment
MKDIR=mkdir
CP=cp
CCADMIN=CCadmin

obj-m += stegreceiver.o

all:
	make -C /usr/lib/modules/`uname -r`/build M=`pwd` modules

clean:
	make -C /usr/lib/modules/`uname -r`/build M=`pwd` clean
