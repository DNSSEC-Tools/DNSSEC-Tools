
INCL= ../libsres
LIB= ../libsres
GCC= gcc -g -Wall -I${INCL}
SRES=-lsres

SRC=  res_squery.c val_support.c res_zone.c 
OBJ=$(SRC:.c=.o)

DRIVER= driver 

all: ${OBJ} ${DRIVER}
                                                                                                                          
clean:
	rm -f ${OBJ} ${DRIVER} resolver_driver.o 
                                                                                                                          
.c.o:
	${GCC} -c $<

${DRIVER}: ${OBJ} resolver_driver.o
	${GCC} -L${LIB} -o $@ $? ${SRES}
                                                                                                                          
