
INCL= ../libsres
LIB= ../libsres
GCC= gcc -g -Wall -I${INCL} -I.
SRES=-lsres -lcrypto

SRC=  	res_squery.c \
	val_support.c \
	res_zone.c \
	val_verify.c \
	val_parse.c \
	val_print.c \
	crypto/val_rsamd5.c \
	crypto/val_rsasha1.c \
	crypto/val_dsasha1.c

OBJ=$(SRC:.c=.o)

DRIVER= driver 
#VALIDATOR=validate (for future)
VALIDATOR= verify

all: ${OBJ} ${DRIVER} ${VALIDATOR}

clean:
	rm -f ${OBJ} ${DRIVER} ${VALIDATOR} resolver_driver.o main.o

.c.o:
	${GCC} -c $< -o $@

${DRIVER}: ${OBJ} resolver_driver.o
	${GCC} -L${LIB} -o $@ $? ${SRES}

${VALIDATOR}: ${OBJ} main.o
	${GCC} -L${LIB} -o $@ $? ${SRES}
