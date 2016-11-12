PROG=	smart
SRCS=	smart.c libsmart.c
SRCS+=	freebsd_dev.c
LDADD= -lcam
MAN=
#CFLAGS+= -ggdb -O0

.include <bsd.prog.mk>
