
SRC=	ns_name.c	\
		support.c \
		res_debug.c	\
		ns_netint.c	\
		ns_print.c	\
		base64.c	\
		ns_samedomain.c	\
		ns_parse.c	\
		ns_ttl.c	\
		res_comp.c	\
		res_mkquery.c \
		res_io_manager.c \
		res_transaction.c \
		res_tsig.c	\
		res_query.c	

OBJ=$(SRC:.c=.o)

LIBRES= libsres.a

INCLUDE= include
GCC= gcc -g -Wall -I${INCLUDE}

all: ${LIBRES} 

clean:
	rm -f ${OBJ} ${LIBRES} 

.c.o:
	${GCC} -c $<

${LIBRES}: ${OBJ}
	ar cruv $@ ${OBJ}
	ranlib $@ 
