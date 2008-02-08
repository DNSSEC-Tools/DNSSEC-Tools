OBJS      = libval_shim.o
LIBNAME   = val_shim
SONAME    = lib$(LIBNAME).so.1.0.0
SOVERSION = lib$(LIBNAME).so.1.0
CFLAGS    = -Wall
CC	  = gcc
LIBS	  = -lsres -lval-threads -lpthread -lcrypto
 
all:    lib$(LIBNAME).so 
 
lib$(LIBNAME).so: $(OBJS)
	$(CC) -shared $(CFLAGS) $(OBJS) -lc $(LIBS) \
           -Wl,-soname -Wl,$(SOVERSION) -o $(SONAME) && \
	ln -sf $(SONAME) $(SOVERSION) && \
	ln -sf $(SONAME) lib$(LIBNAME).so
 
.c.o:
	gcc -fPIC -DPIC $(CFLAGS) -c -o $*.o $<
 
clean:
	rm -f *.o *.a *.so *.so.* *~