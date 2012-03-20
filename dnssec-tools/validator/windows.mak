# compiler options
PERL=perl
CC=cl
CFLAG= /Zi /nologo /W3 /WX- /Od /Gm /RTC1 /GS /fp:precise /Zc:wchar_t /Zc:forScope /Gd /TC /MDd 
CDEFS= /D "i386" /D "WIN32" /D "_DEBUG" /D "_WINDOWS" /D "_USRDLL" /D "_WINDLL" /D "_UNICODE" /D "UNICODE"
INC=/I include
INC=/I \usr\include /I include
SHLIB_CFLAGS=$(CFLAG) $(INC) $(CDEFS)
MKDIR=mkdir

SRC_D=.

LINK=link
LFLAGS64=/INCREMENTAL /NOLOGO /opt:ref /debug /DLL /MANIFEST /SUBSYSTEM:WINDOWS /TLBID:1 /DYNAMICBASE /NXCOMPAT /MACHINE:X64 
LFLAGS32=/INCREMENTAL /NOLOGO /opt:ref /debug /DLL /MANIFEST /SUBSYSTEM:WINDOWS /TLBID:1 /DYNAMICBASE /NXCOMPAT /MACHINE:X86 
EX_LIBS=ws2_32.lib kernel32.lib user32.lib gdi32.lib winspool.lib comdlg32.lib advapi32.lib shell32.lib ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib 
LIB_SSL=/libpath:\usr\lib libeay32.lib ssleay32.lib


OUT_D=Debug

SRC_LIBSRES_D=libsres
TMP_LIBSRES_D=libsres\$(OUT_D)
SRC_LIBVAL_D=libval
TMP_LIBVAL_D=libval\$(OUT_D)

LIBSRES_OBJS = $(TMP_LIBSRES_D)\base64.obj \
	$(TMP_LIBSRES_D)\dllmain.obj \
	$(TMP_LIBSRES_D)\ns_name.obj \
	$(TMP_LIBSRES_D)\ns_netint.obj \
	$(TMP_LIBSRES_D)\ns_parse.obj \
	$(TMP_LIBSRES_D)\ns_print.obj \
	$(TMP_LIBSRES_D)\ns_samedomain.obj \
	$(TMP_LIBSRES_D)\ns_ttl.obj \
	$(TMP_LIBSRES_D)\nsap_addr.obj \
	$(TMP_LIBSRES_D)\res_comp.obj \
	$(TMP_LIBSRES_D)\res_debug.obj \
	$(TMP_LIBSRES_D)\res_io_manager.obj \
	$(TMP_LIBSRES_D)\res_mkquery.obj \
	$(TMP_LIBSRES_D)\res_query.obj \
	$(TMP_LIBSRES_D)\res_support.obj \
	$(TMP_LIBSRES_D)\res_tsig.obj

LIBSRES_DLL = $(OUT_D)\libsres.dll

LIBVAL_OBJS = $(TMP_LIBVAL_D)\dllmain.obj \
	$(TMP_LIBVAL_D)\val_assertion.obj \
	$(TMP_LIBVAL_D)\val_cache.obj \
	$(TMP_LIBVAL_D)\val_context.obj \
	$(TMP_LIBVAL_D)\val_crypto.obj \
	$(TMP_LIBVAL_D)\val_get_rrset.obj \
	$(TMP_LIBVAL_D)\val_getaddrinfo.obj \
	$(TMP_LIBVAL_D)\val_gethostbyname.obj \
	$(TMP_LIBVAL_D)\val_log.obj \
	$(TMP_LIBVAL_D)\val_parse.obj \
	$(TMP_LIBVAL_D)\val_policy.obj \
	$(TMP_LIBVAL_D)\val_resquery.obj \
	$(TMP_LIBVAL_D)\val_support.obj \
	$(TMP_LIBVAL_D)\val_verify.obj \
	$(TMP_LIBVAL_D)\val_x_query.obj

LIBVAL_DLL = $(OUT_D)\libval.dll

	
all: win64

win32: $(OUT_D) libsres libval dll32

win64: $(OUT_D) libsres libval dll64 

libsres: $(TMP_LIBSRES_D) $(LIBSRES_OBJS)

libval: $(TMP_LIBVAL_D) $(LIBVAL_OBJS)

dll32: libsres32 libval32

dll64: libsres64 libval64

clean:
	IF EXIST $(OUT_D) rmdir /S /Q $(OUT_D)
	IF EXIST libsres\$(OUT_D)  rmdir /S /Q libsres\$(OUT_D)
	IF EXIST libval\$(OUT_D)   rmdir /S /Q libval\$(OUT_D)

banner:
	@echo building libraries

$(OUT_D):
	$(MKDIR) "$(OUT_D)"

$(TMP_LIBSRES_D):
	$(MKDIR) "$(TMP_LIBSRES_D)"
	
$(TMP_LIBVAL_D):
	$(MKDIR) "$(TMP_LIBVAL_D)"

	
{$(SRC_LIBSRES_D)}.c{$(TMP_LIBSRES_D)}.obj:
	$(CC) $(SHLIB_CFLAGS) /Fo$(*R).obj -c $<
	
{$(SRC_LIBVAL_D)}.c{$(TMP_LIBVAL_D)}.obj:
	$(CC) $(SHLIB_CFLAGS) /EHsc /GS /Fo$(*R).obj -c $<
	

libsres64: $(LIBSRES_OBJS)
	$(LINK) $(LFLAGS64) /out:$(OUT_D)\libsres.dll @<< $(LIBSRES_OBJS) $(SHLIB_EX_OBJS) $(EX_LIBS) $(LIB_SSL) /DEF:$(SRC_LIBSRES_D)\libsres.def /ManifestFile:"$(TMP_LIBSRES_D)\libsres.dll.intermediate.manifest" 
<<
	IF EXIST $@.manifest mt -nologo -manifest $@.manifest -outputresource:$@;2

libval64: $(LIBVAL_OBJS)
	$(LINK) $(LFLAGS64) /out:$(OUT_D)\libval.dll @<< $(LIBVAL_OBJS) $(SHLIB_EX_OBJS) $(EX_LIBS) $(LIB_SSL) $(OUT_D)\libsres.lib  /DEF:$(SRC_LIBVAL_D)\libval.def  /ManifestFile:"$(TMP_LIBVAL_D)\libval.dll.intermediate.manifest" 
<<
	IF EXIST $@.manifest mt -nologo -manifest $@.manifest -outputresource:$@;2
	
libsres32: $(LIBSRES_OBJS)
	$(LINK) $(LFLAGS32) /out:$(OUT_D)\libsres.dll @<< $(LIBSRES_OBJS) $(SHLIB_EX_OBJS) $(EX_LIBS) $(LIB_SSL) /DEF:$(SRC_LIBSRES_D)\libsres.def /ManifestFile:"$(TMP_LIBSRES_D)\libsres.dll.intermediate.manifest" 
<<
	IF EXIST $@.manifest mt -nologo -manifest $@.manifest -outputresource:$@;2

libval32: $(LIBVAL_OBJS)
	$(LINK) $(LFLAGS32) /out:$(OUT_D)\libval.dll @<< $(LIBVAL_OBJS) $(SHLIB_EX_OBJS) $(EX_LIBS) $(LIB_SSL) $(OUT_D)\libsres.lib  /DEF:$(SRC_LIBVAL_D)\libval.def  /ManifestFile:"$(TMP_LIBVAL_D)\libval.dll.intermediate.manifest" 
<<
	IF EXIST $@.manifest mt -nologo -manifest $@.manifest -outputresource:$@;2
