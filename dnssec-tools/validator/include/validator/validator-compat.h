/* Copyright (c) 1983, 1989
 *    The Regents of the University of California.  All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
/*
 * Copyright 2007-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

#ifndef _VALIDATOR_COMPAT_H
#define _VALIDATOR_COMPAT_H

#ifdef __cplusplus
extern          "C" {
#endif

#ifdef WIN32

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <fcntl.h>
#include <time.h>

#ifndef HAVE_ERRNO_H
#define HAVE_ERRNO_H 1
#endif
#ifndef HAVE_GETOPT_H
#define HAVE_GETOPT_H 1
#endif
#ifndef HAVE_INT16_T
#define HAVE_INT16_T 1
#endif
#ifndef HAVE_INT32_T
#define HAVE_INT32_T 1
#endif
#ifndef HAVE_INT8_T
#define HAVE_INT8_T 1
#endif
#ifndef HAVE_LIBGEN_H
#define HAVE_LIBGEN_H 1
#endif
#ifndef HAVE_LIMITS_H
#define HAVE_LIMITS_H 1
#endif
#ifndef HAVE_MEMORY_H
#define HAVE_MEMORY_H 1
#endif
#ifndef HAVE_SHA_2
#define HAVE_SHA_2 1
#endif
#ifndef HAVE_STDINT_H
#define HAVE_STDINT_H 1
#endif
#ifndef HAVE_STDLIB_H
#define HAVE_STDLIB_H 1
#endif
#ifndef HAVE_STRING_H
#define HAVE_STRING_H 1
#endif
#ifndef HAVE_SYS_STAT_H
#define HAVE_SYS_STAT_H 1
#endif
#ifndef HAVE_SYS_TYPES_H
#define HAVE_SYS_TYPES_H 1
#endif
#ifndef HAVE_FREEADDRINFO
#define HAVE_FREEADDRINFO 1
#endif
#ifndef LIBVAL_DLV
#define LIBVAL_DLV 1
#endif
#ifndef LIBVAL_INLINE_POLICY
#define LIBVAL_INLINE_POLICY 1
#endif
#ifndef LIBVAL_NSEC3
#define LIBVAL_NSEC3 1
#endif
#ifndef R_FUNCS_RETURN_STRUCT
#define R_FUNCS_RETURN_STRUCT 1
#endif
#ifndef STDC_HEADERS
#define STDC_HEADERS 1
#endif
#ifndef VAL_IPV6
#define VAL_IPV6 1
#endif
#ifndef VAL_NO_THREADS
#define VAL_NO_THREADS 1
#endif
#ifndef VAL_CONFIGURATION_FILE
#define VAL_CONFIGURATION_FILE "dnsval.txt"
#endif
#ifndef VAL_RESOLV_CONF
#define VAL_RESOLV_CONF "resolv.txt"
#endif
#ifndef VAL_ROOT_HINTS
#define VAL_ROOT_HINTS "root.txt"
#endif

#endif /* WIN32 */

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif
#ifdef HAVE_STRINGS_H
#include <strings.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYSLOG_H
#include <syslog.h>
#endif
#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETDB_H
#include <netdb.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_LIMITS_H
#include <limits.h>
#endif      
#ifdef HAVE_CTYPE_H 
#include <ctype.h>
#endif
#ifdef HAVE_SYS_FILE_H
#include <sys/file.h>
#endif
#ifdef HAVE_SYS_FCNTL_H
#include <sys/fcntl.h>
#endif
#ifdef HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif
#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif
#ifdef HAVE_SYS_FILIO_H
#include <sys/filio.h>
#endif
#ifdef HAVE_SYS_SELECT_H
#include <sys/select.h>
#endif

#ifdef HAVE_ARPA_NAMESER_H
#include <arpa/nameser.h>
#endif
#ifdef HAVE_ARPA_NAMESER_COMPAT_H
#include <arpa/nameser_compat.h>
#endif 
#ifdef HAVE_RESOLV_H
#include <resolv.h>
#endif    

#ifdef HAVE_ENDIAN_H
#include <endian.h>
#else 
#if (BSD >= 199103)
# include <machine/endian.h>
#endif 
#endif

/* define u_int64_t if not available */
#ifndef HAVE_U_INT64_T
#ifdef WIN32
typedef __int64 u_int64_t;
#else
#ifdef HAVE_UINT64_T
typedef uint64_t        u_int64_t;
#else
#ifdef INT64_T
typedef unsigned INT64_T u_int64_t;
#else
typedef unsigned long long  u_int64_t;
#endif
#endif
#endif
#endif /* !HAVE_U_INT64_T */

/* define u_int32_t if not available */
#ifndef HAVE_U_INT32_T
#ifdef HAVE_UINT32_T
typedef uint32_t        u_int32_t;
#else
#ifdef INT32_T
typedef unsigned INT32_T u_int32_t;
#else
typedef unsigned int     u_int32_t;
#endif
#endif
#endif /* !HAVE_U_INT32_T */

/* define u_int16_t if not available */
#ifndef HAVE_U_INT16_T
#ifdef HAVE_UINT16_T
typedef uint16_t        u_int16_t;
#else
#ifdef INT16_T
typedef unsigned INT16_T u_int16_t;
#else
typedef unsigned short     u_int16_t;
#endif
#endif
#endif /* !HAVE_U_INT16_T */

#ifndef HAVE_U_CHAR 
#define u_char unsigned char 
#endif
#ifndef HAVE_U_SHORT 
#define u_short unsigned short 
#endif
#ifndef HAVE_U_LONG
#define u_long unsigned long 
#endif

#ifndef HAVE_SIZE_T
#define size_t unsigned int
#endif

#ifndef HAVE_SSIZE_T
#define ssize_t int
#endif

#ifndef HAVE_SNPRINTF 
#define snprintf _snprintf
#endif
#ifndef HAVE_STRNCASECMP 
#define strncasecmp _strnicmp
#endif

#ifdef WIN32

int gettimeofday(struct timeval* p, void* tz /* IGNORED */);

#ifndef va_copy
#define va_copy(dst, src) ((void)((dst) = (src)))
#endif

#define getdtablesize() FD_SETSIZE
#define sleep(x) Sleep(x*1000)
#ifndef EWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#endif
#ifndef EMSGSIZE
#define EMSGSIZE WSAEMSGSIZE
#endif
#ifndef INET6_ADDRSTRLEN
#define INET6_ADDRSTRLEN 46
#endif
#define CLOSESOCK closesocket

#endif /* WIN32 */

#ifndef SOCKET_ERROR
#define SOCKET_ERROR -1
#endif
#ifndef INVALID_SOCKET
#define INVALID_SOCKET -1
#endif
#ifndef CLOSESOCK
#  ifdef DEBUG_DONT_CLOSESOCK
#     define CLOSESOCK(x) do { ; } while(0)
#  else
#     define CLOSESOCK close
#  endif
#endif

#ifndef HAVE_SYSLOG_H
#define LOG_EMERG 0
#define LOG_ALERT 1
#define LOG_CRIT 2
#define LOG_ERR 3
#define LOG_WARNING 4
#define LOG_NOTICE 5
#define LOG_INFO 6
#define LOG_DEBUG 7
#endif

#ifdef WIN32
#define INET_NTOP(family, sa, addrlen, buf, buflen, addr) \
    ((WSAAddressToStringA((SOCKADDR *)sa, addrlen,\
                                  NULL, buf, (DWORD *)&buflen) == 0) && ((addr = buf))) 
#define INET_PTON(family, buf, sa, addrlenptr) \
    ((WSAStringToAddressA((LPTSTR)buf, family, NULL, \
                                 (LPSOCKADDR)sa, (LPINT)addrlenptr) == 0) ? 1 : 0)
#else
#define INET_NTOP(family, sa, addrlen, buf, buflen, addr) \
    (addr = (family == AF_INET6) ? inet_ntop(family, &((struct sockaddr_in6 *)sa)->sin6_addr, buf, buflen) :\
               inet_ntop(family, &((struct sockaddr_in *)sa)->sin_addr, buf, buflen))
#define INET_PTON(family, buf, sa, addrlenptr) \
    ((family == AF_INET6) ? inet_pton(family, buf, &((struct sockaddr_in6 *)sa)->sin6_addr) : \
               inet_pton(family, buf, &((struct sockaddr_in *)sa)->sin_addr))
#endif


#ifdef SPRINTF_CHAR
# define SPRINTF(x) strlen(sprintf/**/x)
#else
# define SPRINTF(x) ((size_t)sprintf x)
#endif
#ifndef h_errno                 /* can be a macro */
extern int      h_errno;
#endif

#ifndef NETDB_SUCCESS
#define NETDB_SUCCESS 0
#endif

/* 
 * XXX FreeBSD no longer defines EAI_NODATA. Need to figure out why 
 * this is so. Following is a temporary fix.
 */
#if !defined(EAI_NODATA) && (EAI_NONAME == 8)
#define EAI_NODATA 7
#endif

#ifdef WIN32
#define SET_LAST_ERR(x) WSASetLastError(x) 
#define GET_LAST_ERR() WSAGetLastError() 
#else
#define SET_LAST_ERR(x) do {\
        h_errno = x;\
} while (0)
#define GET_LAST_ERR()  h_errno
#endif

#if WIN32
#define GET_TIME_BUF(tv_sec, time_buf) do {\
    char *c;\
    char *e = time_buf + sizeof(time_buf);;\
    memset(time_buf, 0, sizeof(time_buf));\
    c = ctime(tv_sec);\
    if (c) {\
        strncpy(time_buf, c, sizeof(time_buf));\
        for(c=time_buf; c < e && *c != '\0' && *c != '\n'; c++);\
        if( c < e && *c == '\n')\
            *c = '\0';\
    }\
} while(0)
#elif sun
#define GET_TIME_BUF(tv_sec, time_buf) do {\
    char *c;\
    char *e = time_buf + sizeof(time_buf);;\
    memset(time_buf, 0, sizeof(time_buf));\
    ctime_r(tv_sec, time_buf, sizeof(time_buf));\
    for(c=time_buf; c < e && *c != '\0' && *c != '\n'; c++);\
    if(c < e && *c == '\n')\
        *c = '\0';\
} while(0)
#else
#define GET_TIME_BUF(tv_sec, time_buf) do {\
    char *c;\
    char *e = time_buf + sizeof(time_buf);;\
    memset(time_buf, 0, sizeof(time_buf));\
    ctime_r(tv_sec, time_buf);\
    for(c=time_buf; c < e && *c != '\0' && *c != '\n'; c++);\
    if(c < e && *c == '\n')\
        *c = '\0';\
} while(0)
#endif

#ifndef BYTE_ORDER
#define	LITTLE_ENDIAN	1234	/* least-significant byte first (vax, pc) */
#define	BIG_ENDIAN	4321	/* most-significant byte first (IBM, net) */
#define	PDP_ENDIAN	3412	/* LSB first in word, MSW first in long (pdp)*/
#if defined(vax) || defined(ns32000) || defined(sun386) || defined(i386) || \
    defined(MIPSEL) || defined(_MIPSEL) || defined(BIT_ZERO_ON_RIGHT) || \
    defined(__alpha__) || defined(__alpha) || defined(_X86_) || \
    (defined(__Lynx__) && defined(__x86__))
#define BYTE_ORDER	LITTLE_ENDIAN
#endif

#if defined(sel) || defined(pyr) || defined(mc68000) || defined(sparc) || \
    defined(is68k) || defined(tahoe) || defined(ibm032) || defined(ibm370) || \
    defined(MIPSEB) || defined(_MIPSEB) || defined(_IBMR2) || defined(DGUX) ||\
    defined(apollo) || defined(__convex__) || defined(_CRAY) || \
    defined(__hppa) || defined(__hp9000) || \
    defined(__hp9000s300) || defined(__hp9000s700) || \
    defined(__hp3000s900) || defined(MPE) || \
    defined (BIT_ZERO_ON_LEFT) || defined(m68k) || \
    (defined(__Lynx__) && \
     (defined(__68k__) || defined(__sparc__) || defined(__powerpc__)))
#define BYTE_ORDER	BIG_ENDIAN
#endif
#endif /* BYTE_ORDER */

#if !defined(BYTE_ORDER) || \
    (BYTE_ORDER != BIG_ENDIAN && BYTE_ORDER != LITTLE_ENDIAN && \
    BYTE_ORDER != PDP_ENDIAN)
	/* you must determine what the correct bit order is for
	 * your compiler - the next line is an intentional error
	 * which will force your compiles to bomb until you fix
	 * the above macros.
	 */
  error "Undefined or invalid BYTE_ORDER";
#endif

#ifndef NAMESER_HAS_HEADER
/*
 * Structure for query header.  The order of the fields is machine- and
 * compiler-dependent, depending on the byte/bit order and the layout
 * of bit fields.  We use bit fields only in int variables, as this
 * is all ANSI requires.  This requires a somewhat confusing rearrangement.
 */

typedef struct {
	unsigned	id :16;		/* query identification number */
#if BYTE_ORDER == BIG_ENDIAN
			/* fields in third byte */
	unsigned	qr: 1;		/* response flag */
	unsigned	opcode: 4;	/* purpose of message */
	unsigned	aa: 1;		/* authoritive answer */
	unsigned	tc: 1;		/* truncated message */
	unsigned	rd: 1;		/* recursion desired */
			/* fields in fourth byte */
	unsigned	ra: 1;		/* recursion available */
	unsigned	unused :1;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	ad: 1;		/* authentic data from named */
	unsigned	cd: 1;		/* checking disabled by resolver */
	unsigned	rcode :4;	/* response code */
#endif
#if BYTE_ORDER == LITTLE_ENDIAN || BYTE_ORDER == PDP_ENDIAN
			/* fields in third byte */
	unsigned	rd :1;		/* recursion desired */
	unsigned	tc :1;		/* truncated message */
	unsigned	aa :1;		/* authoritive answer */
	unsigned	opcode :4;	/* purpose of message */
	unsigned	qr :1;		/* response flag */
			/* fields in fourth byte */
	unsigned	rcode :4;	/* response code */
	unsigned	cd: 1;		/* checking disabled by resolver */
	unsigned	ad: 1;		/* authentic data from named */
	unsigned	unused :1;	/* unused bits (MBZ as of 4.9.3a3) */
	unsigned	ra :1;		/* recursion available */
#endif
			/* remaining bytes */
	unsigned	qdcount :16;	/* number of question entries */
	unsigned	ancount :16;	/* number of answer entries */
	unsigned	nscount :16;	/* number of authority entries */
	unsigned	arcount :16;	/* number of resource entries */
} HEADER;

#endif

#if !defined(HAVE_RESOLV_H) || defined(eabi) || defined(ANDROID) 
#define RES_INIT        0x00000001      /* address initialized */
#define RES_DEBUG       0x00000002      /* print debug messages */
#define RES_AAONLY      0x00000004      /* authoritative answers only (!IMPL)*/
#define RES_USEVC       0x00000008      /* use virtual circuit */
#define RES_PRIMARY     0x00000010      /* query primary server only (!IMPL) */
#define RES_IGNTC       0x00000020      /* ignore trucation errors */
#define RES_RECURSE     0x00000040      /* recursion desired */
#define RES_DEFNAMES    0x00000080      /* use default domain name */
#define RES_STAYOPEN    0x00000100      /* Keep TCP socket open */
#define RES_DNSRCH      0x00000200      /* search up local domain tree */
#define RES_INSECURE1   0x00000400      /* type 1 security disabled */
#define RES_INSECURE2   0x00000800      /* type 2 security disabled */
#define RES_NOALIASES   0x00001000      /* shuts off HOSTALIASES feature */
#define RES_USE_INET6   0x00002000      /* use/map IPv6 in gethostbyname() */
#define RES_ROTATE      0x00004000      /* rotate ns list after each query */
#define RES_NOCHECKNAME 0x00008000      /* do not check names for sanity. */
#define RES_KEEPTSIG    0x00010000      /* do not strip TSIG records */
#define RES_BLAST       0x00020000      /* blast all recursive servers */
#define RES_NO_NIBBLE   0x00040000      /* disable IPv6 nibble mode reverse */
#define RES_NO_BITSTRING 0x00080000     /* disable IPv6 bitstring mode reverse */
#define RES_NOTLDQUERY  0x00100000      /* don't unqualified name as a tld */
#define RES_USE_DNSSEC  0x00200000      /* use DNSSEC using OK bit in OPT */
/* KAME extensions: use higher bit to avoid conflict with ISC use */
#define RES_USE_DNAME   0x10000000      /* use DNAME */
#define RES_USE_A6      0x20000000      /* use A6 */
#define RES_USE_EDNS0   0x40000000      /* use EDNS0 if configured */
#define RES_NO_NIBBLE2  0x80000000      /* disable alternate nibble lookup */

#define RES_DEFAULT     (RES_RECURSE | RES_DEFNAMES | RES_DNSRCH | RES_INSECURE1)

/*
 * Resolver "pfcode" values.  Used by dig.
 */
#define RES_PRF_STATS   0x00000001
#define RES_PRF_UPDATE  0x00000002
#define RES_PRF_CLASS   0x00000004
#define RES_PRF_CMD     0x00000008
#define RES_PRF_QUES    0x00000010
#define RES_PRF_ANS     0x00000020
#define RES_PRF_AUTH    0x00000040
#define RES_PRF_ADD     0x00000080
#define RES_PRF_HEAD1   0x00000100
#define RES_PRF_HEAD2   0x00000200
#define RES_PRF_TTLID   0x00000400
#define RES_PRF_HEADX   0x00000800
#define RES_PRF_QUERY   0x00001000
#define RES_PRF_REPLY   0x00002000
#define RES_PRF_INIT    0x00004000
#define RES_PRF_TRUNC   0x00008000
/*                      0x00010000      */
#endif /* HAVE_RESOLV_H */

/*
 * OpenBSD has t_*, but not ns_t_*
 */
#if ! HAVE_DECL_NS_T_A
/*
 * Currently defined type values for resources and queries.
 */
typedef enum __ns_type {
	ns_t_invalid = 0,	/* Cookie. */
	ns_t_a = 1,		/* Host address. */
	ns_t_ns = 2,		/* Authoritative server. */
	ns_t_md = 3,		/* Mail destination. */
	ns_t_mf = 4,		/* Mail forwarder. */
	ns_t_cname = 5,		/* Canonical name. */
	ns_t_soa = 6,		/* Start of authority zone. */
	ns_t_mb = 7,		/* Mailbox domain name. */
	ns_t_mg = 8,		/* Mail group member. */
	ns_t_mr = 9,		/* Mail rename name. */
	ns_t_null = 10,		/* Null resource record. */
	ns_t_wks = 11,		/* Well known service. */
	ns_t_ptr = 12,		/* Domain name pointer. */
	ns_t_hinfo = 13,	/* Host information. */
	ns_t_minfo = 14,	/* Mailbox information. */
	ns_t_mx = 15,		/* Mail routing information. */
	ns_t_txt = 16,		/* Text strings. */
	ns_t_rp = 17,		/* Responsible person. */
	ns_t_afsdb = 18,	/* AFS cell database. */
	ns_t_x25 = 19,		/* X_25 calling address. */
	ns_t_isdn = 20,		/* ISDN calling address. */
	ns_t_rt = 21,		/* Router. */
	ns_t_nsap = 22,		/* NSAP address. */
	ns_t_nsap_ptr = 23,	/* Reverse NSAP lookup (deprecated). */
	ns_t_sig = 24,		/* Security signature. */
	ns_t_key = 25,		/* Security key. */
	ns_t_px = 26,		/* X.400 mail mapping. */
	ns_t_gpos = 27,		/* Geographical position (withdrawn). */
	ns_t_aaaa = 28,		/* Ip6 Address. */
	ns_t_loc = 29,		/* Location Information. */
	ns_t_nxt = 30,		/* Next domain (security). */
	ns_t_eid = 31,		/* Endpoint identifier. */
	ns_t_nimloc = 32,	/* Nimrod Locator. */
	ns_t_srv = 33,		/* Server Selection. */
	ns_t_atma = 34,		/* ATM Address */
	ns_t_naptr = 35,	/* Naming Authority PoinTeR */
	ns_t_kx = 36,		/* Key Exchange */
	ns_t_cert = 37,		/* Certification record */
	ns_t_a6 = 38,		/* IPv6 address (deprecates AAAA) */
	ns_t_dname = 39,	/* Non-terminal DNAME (for IPv6) */
	ns_t_sink = 40,		/* Kitchen sink (experimentatl) */
	ns_t_opt = 41,		/* EDNS0 option (meta-RR) */
	ns_t_tsig = 250,	/* Transaction signature. */
	ns_t_ixfr = 251,	/* Incremental zone transfer. */
	ns_t_axfr = 252,	/* Transfer zone of authority. */
	ns_t_mailb = 253,	/* Transfer mailbox records. */
	ns_t_maila = 254,	/* Transfer mail agent records. */
	ns_t_any = 255,		/* Wildcard match. */
	ns_t_zxfr = 256,	/* BIND-specific, nonstandard. */
	ns_t_max = 65536
} ns_type;


/*
 * Values for class field
 */
typedef enum __ns_class {
        ns_c_invalid = 0,       /* Cookie. */
        ns_c_in = 1,            /* Internet. */
        ns_c_2 = 2,             /* unallocated/unsupported. */
        ns_c_chaos = 3,         /* MIT Chaos-net. */
        ns_c_hs = 4,            /* MIT Hesiod. */
        /* Query class values which do not appear in resource records */
        ns_c_none = 254,        /* for prereq. sections in update requests */
        ns_c_any = 255,         /* Wildcard match. */
        ns_c_max = 65536
} ns_class;

/*
 * Currently defined opcodes.
 */
typedef enum __ns_opcode {
        ns_o_query = 0,         /* Standard query. */
        ns_o_iquery = 1,        /* Inverse query (deprecated/unsupported). */
        ns_o_status = 2,        /* Name server status query (unsupported). */
                                /* Opcode 3 is undefined/reserved. */
        ns_o_notify = 4,        /* Zone change notification. */
        ns_o_update = 5,        /* Zone update message. */
        ns_o_max = 6
} ns_opcode;

/*
 * Currently defined response codes.
 */
typedef enum __ns_rcode {
        ns_r_noerror = 0,       /* No error occurred. */
        ns_r_formerr = 1,       /* Format error. */
        ns_r_servfail = 2,      /* Server failure. */
        ns_r_nxdomain = 3,      /* Name error. */
        ns_r_notimpl = 4,       /* Unimplemented. */
        ns_r_refused = 5,       /* Operation refused. */
        /* these are for BIND_UPDATE */
        ns_r_yxdomain = 6,      /* Name exists */
        ns_r_yxrrset = 7,       /* RRset exists */
        ns_r_nxrrset = 8,       /* RRset does not exist */
        ns_r_notauth = 9,       /* Not authoritative for zone */
        ns_r_notzone = 10,      /* Zone of record different from zone section */
        ns_r_max = 11,
        /* The following are TSIG extended errors */
        ns_r_badsig = 16,
        ns_r_badkey = 17,
        ns_r_badtime = 18
} ns_rcode;

#endif /* HAVE_DECL_NS_T_A */

/*
 * FreeBSD is missing ns_t_kx, ns_t_cert, ns_t_a6, ns_t_dname, ns_t_sink, ns_t_tsig, ns_t_zxfr
 * for now, assume if the first is missing, the rest are too. If we hit system that has some
 * but not others, tweak accordingly.
 */
#if defined HAVE_DECL_NS_T_KX && !HAVE_DECL_NS_T_KX
#define ns_t_kx      36  /* Key Exchange */
#define ns_t_cert    37  /* Certification record */
#define ns_t_a6      38  /* IPv6 address (deprecates AAAA) */
#define ns_t_dname   39  /* Non-terminal DNAME (for IPv6) */
#define ns_t_sink    40  /* Kitchen sink (experimentatl) */
#define ns_t_tsig    250 /* Transaction signature. */
#define ns_t_zxfr    256 /* BIND-specific, nonstandard. */
#endif /* HAVE_NS_T_KX */

#if !HAVE_DECL_NS_T_DS
#define ns_t_ds       43
#endif
#if !HAVE_DECL_NS_T_DNSKEY
#define ns_t_dnskey   48
#endif
#if !HAVE_DECL_NS_T_RRSIG
#define ns_t_rrsig    46
#endif
#if !HAVE_DECL_NS_T_NSEC
#define ns_t_nsec     47
#endif
#if !HAVE_DECL_NS_T_TLSA
#define ns_t_tlsa     52 
#endif

#ifdef LIBVAL_NSEC3
#if !HAVE_DECL_NS_T_NSEC3
#define ns_t_nsec3   50
#endif
#endif

#ifdef LIBVAL_DLV
#if !HAVE_DECL_NS_T_DLV
#define ns_t_dlv 32769
#endif
#endif

/*
 * FreeBSD is missing ns_r_badsig, ns_r_badkey, ns_r_badtime
 * for now, assume if the first is missing, the rest are too. If we hit system that has some
 * but not others, tweak accordingly.
 */
#if defined HAVE_DECL_NS_R_BADSIG && !HAVE_DECL_NS_R_BADSIG
#define ns_r_badsig      16
#define ns_r_badkey      17
#define ns_r_badtime     18
#endif /* HAVE_NS_R_BADSIG */

/* eabi = android */
/* OpenBSD has arpa/nameser.h, but it doesn't define ns_msg */
#if !defined(HAVE_ARPA_NAMESER_H) || defined(eabi) || defined(ANDROID) ||defined(__OpenBSD__)
/*
 * Define constants based on RFC 883, RFC 1034, RFC 1035
 */
#define NS_PACKETSZ     512     /* maximum packet size */
#define NS_MAXDNAME     1025    /* maximum domain name */
#define NS_MAXCDNAME    255     /* maximum compressed domain name */
#define NS_MAXLABEL     63      /* maximum length of domain label */
#define NS_HFIXEDSZ     12      /* #/bytes of fixed data in header */
#define NS_QFIXEDSZ     4       /* #/bytes of fixed data in query */
#define NS_RRFIXEDSZ    10      /* #/bytes of fixed data in r record */
#define NS_INT32SZ      4       /* #/bytes of data in a u_int32_t */
#define NS_INT16SZ      2       /* #/bytes of data in a u_int16_t */
#define NS_INT8SZ       1       /* #/bytes of data in a u_int8_t */
#define NS_INADDRSZ     4       /* IPv4 T_A */
#define NS_IN6ADDRSZ    16      /* IPv6 T_AAAA */
#define NS_CMPRSFLGS    0xc0    /* Flag bits indicating name compression. */
#define NS_DEFAULTPORT  53      /* For both TCP and UDP. */

/*
 * These can be expanded with synonyms, just keep ns_parse.c:ns_parserecord()
 * in synch with it.
 */
typedef enum __ns_sect {
        ns_s_qd = 0,            /* Query: Question. */
        ns_s_zn = 0,            /* Update: Zone. */
        ns_s_an = 1,            /* Query: Answer. */
        ns_s_pr = 1,            /* Update: Prerequisites. */
        ns_s_ns = 2,            /* Query: Name servers. */
        ns_s_ud = 2,            /* Update: Update. */
        ns_s_ar = 3,            /* Query|Update: Additional records. */
        ns_s_max = 4
} ns_sect;

/*
 * This is a message handle.  It is caller allocated and has no dynamic data.
 * This structure is intended to be opaque to all but ns_parse.c, thus the
 * leading _'s on the member names.  Use the accessor functions, not the _'s.
 */
typedef struct __ns_msg {
        const u_char    *_msg, *_eom;
        u_int16_t       _id, _flags, _counts[ns_s_max];
        const u_char    *_sections[ns_s_max];
        ns_sect         _sect;
        int             _rrnum;
        const u_char    *_msg_ptr;
} ns_msg;

/* Private data structure - do not use from outside library. */
struct _ns_flagdata {  int mask, shift;  };
extern struct _ns_flagdata _ns_flagdata[];

/* Accessor macros - this is part of the public interface. */

#define ns_msg_id(handle) ((handle)._id + 0)
#define ns_msg_base(handle) ((handle)._msg + 0)
#define ns_msg_end(handle) ((handle)._eom + 0)
#define ns_msg_size(handle) ((handle)._eom - (handle)._msg)
#define ns_msg_count(handle, section) ((handle)._counts[section] + 0)

/*
 * This is a parsed record.  It is caller allocated and has no dynamic data.
 */
typedef struct __ns_rr {
        char            name[NS_MAXDNAME];
        u_int16_t       type;
        u_int16_t       rr_class;
        u_int32_t       ttl;
        u_int16_t       rdlength;
        const u_char *  rdata;
} ns_rr;

/* Accessor macros - this is part of the public interface. */
#define ns_rr_name(rr)  (((rr).name[0] != '\0') ? (rr).name : ".")
#define ns_rr_type(rr)  ((ns_type)((rr).type + 0))
#define ns_rr_class(rr) ((ns_class)((rr).rr_class + 0))
#define ns_rr_ttl(rr)   ((rr).ttl + 0)
#define ns_rr_rdlen(rr) ((rr).rdlength + 0)
#define ns_rr_rdata(rr) ((rr).rdata + 0)

/*
 * These don't have to be in the same order as in the packet flags word,
 * and they can even overlap in some cases, but they will need to be kept
 * in synch with ns_parse.c:ns_flagdata[].
 */
typedef enum __ns_flag {
        ns_f_qr,                /* Question/Response. */
        ns_f_opcode,            /* Operation code. */
        ns_f_aa,                /* Authoritative Answer. */
        ns_f_tc,                /* Truncation occurred. */
        ns_f_rd,                /* Recursion Desired. */
        ns_f_ra,                /* Recursion Available. */
        ns_f_z,                 /* MBZ. */
        ns_f_ad,                /* Authentic Data (DNSSEC). */
        ns_f_cd,                /* Checking Disabled (DNSSEC). */
        ns_f_rcode,             /* Response code. */
        ns_f_max
} ns_flag;

/* Protocol values  */
/* value 0 is reserved */
#define NS_KEY_PROT_TLS         1
#define NS_KEY_PROT_EMAIL       2
#define NS_KEY_PROT_DNSSEC      3
#define NS_KEY_PROT_IPSEC       4
#define NS_KEY_PROT_ANY         255

/* Signatures */
#define NS_MD5RSA_MIN_BITS       512    /* Size of a mod or exp in bits */
#define NS_MD5RSA_MAX_BITS      2552
        /* Total of binary mod and exp */
#define NS_MD5RSA_MAX_BYTES     ((NS_MD5RSA_MAX_BITS+7/8)*2+3)
        /* Max length of text sig block */
#define NS_MD5RSA_MAX_BASE64    (((NS_MD5RSA_MAX_BYTES+2)/3)*4)
#define NS_MD5RSA_MIN_SIZE      ((NS_MD5RSA_MIN_BITS+7)/8)
#define NS_MD5RSA_MAX_SIZE      ((NS_MD5RSA_MAX_BITS+7)/8)

#define NS_DSA_SIG_SIZE         41
#define NS_DSA_MIN_SIZE         213
#define NS_DSA_MAX_BYTES        405

/* Offsets into SIG record rdata to find various values */
#define NS_SIG_TYPE     0       /* Type flags */
#define NS_SIG_ALG      2       /* Algorithm */
#define NS_SIG_LABELS   3       /* How many labels in name */
#define NS_SIG_OTTL     4       /* Original TTL */
#define NS_SIG_EXPIR    8       /* Expiration time */
#define NS_SIG_SIGNED   12      /* Signature time */
#define NS_SIG_FOOT     16      /* Key footprint */
#define NS_SIG_SIGNER   18      /* Domain name of who signed it */

/* How RR types are represented as bit-flags in NXT records */
#define NS_NXT_BITS 8
#define NS_NXT_BIT_SET(  n,p) (p[(n)/NS_NXT_BITS] |=  (0x80>>((n)%NS_NXT_BITS)))
#define NS_NXT_BIT_CLEAR(n,p) (p[(n)/NS_NXT_BITS] &= ~(0x80>>((n)%NS_NXT_BITS)))
#define NS_NXT_BIT_ISSET(n,p) (p[(n)/NS_NXT_BITS] &   (0x80>>((n)%NS_NXT_BITS)))
#define NS_NXT_MAX 127

/*
 * Inline versions of get/put short/long.  Pointer is advanced.
 */
#define NS_GET16(s, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)

#define NS_GET32(l, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (l) = ((u_int32_t)t_cp[0] << 24) \
            | ((u_int32_t)t_cp[1] << 16) \
            | ((u_int32_t)t_cp[2] << 8) \
            | ((u_int32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)

#define NS_PUT16(s, cp) do { \
        register u_int16_t t_s = (u_int16_t)(s); \
        register u_char *t_cp = (u_char *)(cp); \
        *t_cp++ = t_s >> 8; \
        *t_cp   = t_s; \
        (cp) += NS_INT16SZ; \
} while (0)

#define NS_PUT32(l, cp) do { \
        register u_int32_t t_l = (u_int32_t)(l); \
        register u_char *t_cp = (u_char *)(cp); \
        *t_cp++ = t_l >> 24; \
        *t_cp++ = t_l >> 16; \
        *t_cp++ = t_l >> 8; \
        *t_cp   = t_l; \
        (cp) += NS_INT32SZ; \
} while (0)

int	ns_name_uncompress(const u_char *, const u_char *,
		const u_char *, char *, size_t);
int	ns_name_compress(const char *, u_char *, size_t,
	  	const u_char **, const u_char **);
int	ns_name_skip(const u_char **, const u_char *);
int	ns_name_ntop(const u_char *, char *, size_t);
int	ns_name_pton(const char *, u_char *, size_t);
int	ns_name_unpack(const u_char *, const u_char *,
		const u_char *, u_char *, size_t);
int	ns_parserr(ns_msg *, ns_sect, int, ns_rr *);
int	ns_sprintrr(const ns_msg *, const ns_rr *,
	        const char *, const char *, char *, size_t);
int	ns_sprintrrf(const u_char *, size_t, const char *,
		ns_class, ns_type, u_long, const u_char *,
		size_t, const char *, const char *,
		char *, size_t);
int	ns_sprintrrf_data(const u_char *, size_t, const char *,
		ns_class, ns_type, u_long, const u_char *,
		size_t, const char *,
		char *, size_t);
int	ns_initparse(const u_char *, int, ns_msg *);
int	ns_format_ttl(u_long, char *, size_t);
int	ns_parse_ttl(const char *, u_long *);


#endif /* HAVE_ARPA_NAMESER_H */

int libsres_msg_getflag(ns_msg han, int flag);
/*
 * at one open ns_msg_getflag was a macro on Linux, but now it is a
 * function in libresolv. redifine to use our internal version.
 */
#ifndef ns_msg_getflag
#define ns_msg_getflag libsres_msg_getflag
#endif

#ifndef HAVE_FREEADDRINFO
#define freeaddrinfo val_freeaddrinfo
#endif


#ifndef HAVE_DECL_NS_SAMENAME
int             ns_samename(const char *a, const char *b);
int             ns_samedomain(const char *a, const char *b);
#endif

#if !HAVE_DECL_P_SECTION
const char     *p_section(int section, int opcode);
#endif

#if !HAVE_DECL_P_CLASS
const char     *p_class(int pclass);
#endif

const char     *p_sres_type(int type);
#undef p_type
#define p_type(type) p_sres_type(type)


#ifndef NS_MAXDNAME
#define NS_MAXDNAME 1025        /* maximum domain name */
#endif
#ifndef NS_MAXCDNAME
#define NS_MAXCDNAME    255     /* maximum compressed domain name */
#endif
#define DNAME_MAX     1024
#if !defined(NS_MAXCDNAME) && defined (MAXCDNAME)
#define NS_MAXCDNAME MAXCDNAME
#endif
#ifndef NS_CMPRSFLGS
#define NS_CMPRSFLGS   0xc0
#endif

#ifndef RES_RETRY
#define RES_RETRY 1 /* number of times to retry */
#endif
#ifndef RES_TIMEOUT
#define RES_TIMEOUT 5 /* min seconds between retries */
#endif
#ifndef RES_EDNS0_DEFAULT
#define RES_EDNS0_DEFAULT 4096
#endif

#if !defined(NS_INT16SZ) && defined(INT16SZ)
#define NS_INT16SZ INT16SZ
#define NS_INT32SZ INT32SZ
#endif

#define VAL_GET16(s, cp) do { \
            register const u_char *t_cp = (const u_char *)(cp); \
            (s) = ((u_int16_t)t_cp[0] << 8) \
                | ((u_int16_t)t_cp[1]) \
                ; \
            (cp) += NS_INT16SZ; \
} while (0)

#define VAL_GET32(l, cp) do { \
            register const u_char *t_cp = (const u_char *)(cp); \
            (l) = ((u_int32_t)t_cp[0] << 24) \
                | ((u_int32_t)t_cp[1] << 16) \
                | ((u_int32_t)t_cp[2] << 8) \
                | ((u_int32_t)t_cp[3]) \
                ; \
            (cp) += NS_INT32SZ; \
} while (0)

#if !defined(NS_PUT16) && defined(PUTSHORT)
#define NS_PUT16 PUTSHORT
#define NS_PUT32 PUTLONG
#endif

#if 0

#ifndef HAVE_DECL_STRUCT_ADDRINFO
struct addrinfo {
    int ai_flags; 
    int ai_family;
    int ai_socktype;
    int ai_protocol;
    size_t ai_addrlen;
    char    *ai_canonname;
    struct  sockaddr *ai_addr;
    struct  addrinfo *ai_next;
};
#endif

#endif


#ifdef MEMORY_DEBUGGING
#define MALLOC(s) my_malloc(s, __FILE__, __LINE__)
#define FREE(p) my_free(p,__FILE__,__LINE__)
#define STRDUP(p) my_strdup(p,__FILE__,__LINE__)
#else
#define MALLOC(s) malloc(s)
#define FREE(p) free(p)
#define STRDUP(p) strdup(p)
#endif



#ifdef __cplusplus
}                               /* extern "C" */
#endif


/* The Algorithm field of the KEY and SIG RR's is an integer, {1..254} */
#define NS_ALG_MD5RSA           1       /* MD5 with RSA */
#define NS_ALG_DH               2       /* Diffie Hellman KEY */
#define NS_ALG_DSA              3       /* DSA KEY */
#define NS_ALG_DSS              NS_ALG_DSA
#define NS_ALG_EXPIRE_ONLY      253     /* No alg, no security */
#define NS_ALG_PRIVATE_OID      254     /* Key begins with OID giving alg */
#define	ns_t_zxfr 256

#define NS_MD5RSA_MIN_BITS       512    /* Size of a mod or exp in bits */
#define NS_MD5RSA_MAX_BITS      2552
        /* Total of binary mod and exp */
#define NS_MD5RSA_MAX_BYTES     ((NS_MD5RSA_MAX_BITS+7/8)*2+3)
        /* Max length of text sig block */
#define NS_MD5RSA_MAX_BASE64    (((NS_MD5RSA_MAX_BYTES+2)/3)*4)
#define NS_MD5RSA_MIN_SIZE      ((NS_MD5RSA_MIN_BITS+7)/8)
#define NS_MD5RSA_MAX_SIZE      ((NS_MD5RSA_MAX_BITS+7)/8)

#include "openssl/hmac.h"
#include "openssl/ossl_typ.h"

#endif /* _VALIDATOR_COMPAT_H */

