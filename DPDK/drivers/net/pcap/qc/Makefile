
CC=gcc
QAT_INCLUDE	= -I$(ICP_ROOT)/quickassist/include 		\
		  -I$(ICP_ROOT)/quickassist/include/dc 		\
		  -I$(ICP_ROOT)/quickassist/lookaside/access_layer/include
USDM_INCLUDE	= -I$(ICP_ROOT)/quickassit/utilities/libusdm_drv
QATZIP_INCLUDE	= -I$(QATZIP_ROOT)/include -I$(QATZIP_ROOT)/src
#CFLAGS		= $(QAT_INCLUDE) $(USDM_INCLUDE) $(QATZIP_INCLUDE) -DQZ_COOKIE_DEBUG -g
CFLAGS		= $(QAT_INCLUDE) $(USDM_INCLUDE) $(QATZIP_INCLUDE) -g
LDLIBS		= -lz -lqatzip

all: qzip_cookie_test calgary

qzip_cookie_test: qzip_cookie_test.c qzip_cookie.c
	$(CC) $^ -o $@ $(CFLAGS) $(LDLIBS)

calgary:
	./gen_calgary.sh

cscope:
	cscope -bqR

clean:
	rm -f *.o qzip_cookie_test *.out

.PHONY: all qzip_cookie_test cscope clean calgary
