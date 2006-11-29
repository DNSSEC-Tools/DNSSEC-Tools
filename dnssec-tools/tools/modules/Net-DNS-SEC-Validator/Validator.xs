/* -*- C -*-
     Validator.xs -- Perl 5 interface to the Dnssec-Tools validating resolver

     written by G. S. Marzot (marz@users.sourceforge.net)


     Copyright (c) 2006 SPARTA, Inc.  All rights reserved.

     Copyright (c) 2006 G. S. Marzot. All rights reserved.

     This program is free software; you can redistribute it and/or
     modify it under the same terms as Perl itself.
*/
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "validator-config.h"

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <resolv.h>

#include <arpa/nameser.h>
#include <resolver.h>
#include <validator.h>


#define PVAL_BUFSIZE	(16*1024)
#define ADDRINFO_TYPE		0
#define VAL_ADDRINFO_TYPE	1

typedef struct val_context ValContext;

#if 0
static void
print_addrinfo(int type, void *ainfo, char *obuf)
{
    struct sockaddr_in *s_inaddr = NULL;
    struct sockaddr_in6 *s_in6addr = NULL;
    struct addrinfo *a = (struct addrinfo *) ainfo;
    char            buf[INET6_ADDRSTRLEN];

    while (a != NULL) {
        printf("{\n");
        printf("\tFlags:     %d [", a->ai_flags);
        if (a->ai_flags & AI_PASSIVE)
            printf("AI_PASSIVE ");
        if (a->ai_flags & AI_CANONNAME)
            printf("AI_CANONNAME ");
        if (a->ai_flags & AI_NUMERICHOST)
            printf("AI_NUMERICHOST ");
        if (a->ai_flags & AI_V4MAPPED)
            printf("AI_V4MAPPED ");
        if (a->ai_flags & AI_ALL)
            printf("AI_ALL ");
        if (a->ai_flags & AI_ADDRCONFIG)
            printf("AI_ADDRCONFIG ");
        //              if (a->ai_flags & AI_NUMERICSERV) printf("AI_NUMERICSERV ");
        printf("]\n");
        printf("\tFamily:    %d [%s]\n", a->ai_family,
               (a->ai_family == AF_UNSPEC) ? "AF_UNSPEC" :
               (a->ai_family == AF_INET) ? "AF_INET" :
               (a->ai_family == AF_INET6) ? "AF_INET6" : "Unknown");
        printf("\tSockType:  %d [%s]\n", a->ai_socktype,
               (a->ai_socktype == SOCK_STREAM) ? "SOCK_STREAM" :
               (a->ai_socktype == SOCK_DGRAM) ? "SOCK_DGRAM" :
               (a->ai_socktype == SOCK_RAW) ? "SOCK_RAW" : "Unknown");
        printf("\tProtocol:  %d [%s]\n", a->ai_protocol,
               (a->ai_protocol == IPPROTO_IP) ? "IPPROTO_IP" :
               (a->ai_protocol == IPPROTO_TCP) ? "IPPROTO_TCP" :
               (a->ai_protocol == IPPROTO_UDP) ? "IPPROTO_UDP" :
               "Unknown");
        printf("\tAddrLen:   %d\n", a->ai_addrlen);

        if (a->ai_addr != NULL) {
            printf("\tAddrPtr:   %p\n", a->ai_addr);
            if (a->ai_family == AF_INET) {
                s_inaddr = (struct sockaddr_in *) (a->ai_addr);
                printf("\tAddr:      %s\n",
                       inet_ntop(AF_INET,
                                 &(s_inaddr->sin_addr),
                                 buf, INET6_ADDRSTRLEN));
            } else if (a->ai_family == AF_INET6) {
                s_in6addr = (struct sockaddr_in6 *) (a->ai_addr);
                printf("\tAddr:      %s\n",
                       inet_ntop(AF_INET6,
                                 &(s_in6addr->sin6_addr),
                                 buf, INET6_ADDRSTRLEN));
            } else
                printf
                    ("\tAddr:      Cannot parse address. Unknown protocol family\n");
        } else
            printf("\tAddr:      (null)\n");

        if (a->ai_canonname) {
            printf("\tCanonName: %s\n", a->ai_canonname);
	    strcpy(obuf, a->ai_canonname);
        } else {
            printf("\tCanonName: (null)\n");
	    strcpy(obuf, "");
	}

        if (type == VAL_ADDRINFO_TYPE) {
            printf("\tValStatus: %s\n",
                   p_val_error(((struct val_addrinfo *) a)->
                               ai_val_status));
        }
        printf("}\n");

        a = (struct addrinfo *) (a->ai_next);
    }
}

static int
not_here(s)
char *s;
{
    croak("%s not implemented on this architecture", s);
    return -1;
}
#endif


static struct addrinfo *ainfo_sv2c(SV *ainfo_ref, struct addrinfo *ainfo_ptr)
{
  if (ainfo_ptr) {
    bzero(ainfo_ptr, sizeof(struct addrinfo));
    if (ainfo_ref && SvROK(ainfo_ref)) {
      SV **flags_svp = hv_fetch((HV*)SvRV(ainfo_ref), "flags", 5, 1);
      SV **family_svp = hv_fetch((HV*)SvRV(ainfo_ref), "family", 6, 1);
      SV **socktype_svp = hv_fetch((HV*)SvRV(ainfo_ref), "socktype", 8, 1);
      SV **protocol_svp = hv_fetch((HV*)SvRV(ainfo_ref), "protocol", 8, 1);
      SV **addr_svp = hv_fetch((HV*)SvRV(ainfo_ref), "addr", 4, 1);
      SV **canonname_svp = hv_fetch((HV*)SvRV(ainfo_ref), "canonname", 9, 1);

      ainfo_ptr->ai_flags = (SvOK(*flags_svp) ? SvIV(*flags_svp) : 0);
      ainfo_ptr->ai_family = (SvOK(*family_svp) ? SvIV(*family_svp) : 0);
      ainfo_ptr->ai_socktype = (SvOK(*socktype_svp) ? SvIV(*socktype_svp) : 0);
      ainfo_ptr->ai_protocol = (SvOK(*protocol_svp) ? SvIV(*protocol_svp) : 0);
      if (SvOK(*addr_svp)) {
	ainfo_ptr->ai_addr = (struct sockaddr *) SvPV(*addr_svp,PL_na); // borrowed
	ainfo_ptr->ai_addrlen = SvLEN(*addr_svp);
      } else {
	ainfo_ptr->ai_addr = NULL;
	ainfo_ptr->ai_addrlen = 0;
      }
      ainfo_ptr->ai_canonname = (SvOK(*canonname_svp) ? 
				 SvPV(*canonname_svp,PL_na) : NULL); // borrowed

      // fprintf(stderr, "ainfo_ptr->ai_flags = %d\n", ainfo_ptr->ai_flags);
      // fprintf(stderr, "ainfo_ptr->ai_family = %d\n", ainfo_ptr->ai_family);
      // fprintf(stderr, "ainfo_ptr->ai_socktype = %d\n", ainfo_ptr->ai_socktype);
      // fprintf(stderr, "ainfo_ptr->ai_protocol = %d\n", ainfo_ptr->ai_protocol);
      // fprintf(stderr, "ainfo_ptr->ai_addrlen = %d\n", ainfo_ptr->ai_addrlen);
      // fprintf(stderr,"ainfo_ptr->ai_canonname=%s\n",ainfo_ptr->ai_canonname);
    } else {
      ainfo_ptr = NULL;
    }
  }
  return ainfo_ptr;
}

SV *ainfo_c2sv(struct val_addrinfo *ainfo_ptr)
{
  AV *ainfo_av = newAV();
  SV *ainfo_av_ref = newRV_noinc((SV*)ainfo_av);

  for (;ainfo_ptr != NULL; ainfo_ptr = ainfo_ptr->ai_next) {
    HV *ainfo_hv = newHV();
    SV *ainfo_hv_ref = newRV_noinc((SV*)ainfo_hv);
         
    sv_bless(ainfo_hv_ref, gv_stashpv("Net::addrinfo",0));

    // fprintf(stderr,"::ainfo_ptr->ai_flags=%d\n", ainfo_ptr->ai_flags);
    // fprintf(stderr,"::ainfo_ptr->ai_family=%d\n", ainfo_ptr->ai_family);
    // fprintf(stderr,"::ainfo_ptr->ai_socktype=%d\n", ainfo_ptr->ai_socktype);
    // fprintf(stderr,"::ainfo_ptr->ai_protocol=%d\n", ainfo_ptr->ai_protocol);
    // fprintf(stderr,"::ainfo_ptr->ai_addrlen=%d\n", ainfo_ptr->ai_addrlen);
    //fprintf(stderr,"::ainfo_ptr->ai_canonname=%s\n",ainfo_ptr->ai_canonname);
    hv_store(ainfo_hv, "flags", strlen("flags"), 
	     newSViv(ainfo_ptr->ai_flags), 0);
    hv_store(ainfo_hv, "family", strlen("family"), 
	     newSViv(ainfo_ptr->ai_family), 0);
    hv_store(ainfo_hv, "socktype", strlen("socktype"), 
	     newSViv(ainfo_ptr->ai_socktype), 0);
    hv_store(ainfo_hv, "protocol", strlen("protocol"), 
	     newSViv(ainfo_ptr->ai_protocol), 0);
    hv_store(ainfo_hv, "addr", strlen("addr"), 
	     newSVpv((char*)ainfo_ptr->ai_addr, 
		     ainfo_ptr->ai_addrlen), 0);
    hv_store(ainfo_hv, "canonname", strlen("canonname"), 
	     (ainfo_ptr->ai_canonname ?
	      newSVpv(ainfo_ptr->ai_canonname, 
		      strlen(ainfo_ptr->ai_canonname)) :
	     &PL_sv_undef), 0);
    // special field for validated ainfo
    hv_store(ainfo_hv, "val_status", strlen("val_status"), 
	     newSViv(ainfo_ptr->ai_val_status), 0);

    av_push(ainfo_av, ainfo_hv_ref);
  }  
  return ainfo_av_ref;
}


#include "const-c.inc"

MODULE = Net::DNS::SEC::Validator	PACKAGE = Net::DNS::SEC::Validator	PREFIX = pval

INCLUDE: const-xs.inc

ValContext *
pval_create_context(context=":")
	char * context
	CODE:
	{
	ValContext *vc_ptr=NULL;

	int result = val_create_context(context, &vc_ptr);

	RETVAL = (result == 0 ? vc_ptr : NULL);
	}
	OUTPUT:
	RETVAL

int
pval_switch_policy(ctx=NULL,scope=":")
	ValContext * ctx = (SvROK($arg) ? (ValContext*)SvIV((SV*)SvRV($arg)) : NULL);
	char * scope
	CODE:
	{
	int result = val_switch_policy_scope(ctx, scope);
	RETVAL = result;
	}
	OUTPUT:
	RETVAL

SV *
pval_getaddrinfo(ctx=NULL,node=NULL,service=NULL,hints_ref=NULL)
	ValContext * ctx = (SvROK($arg) ? (ValContext*)SvIV((SV*)SvRV($arg)) : NULL);
        char *	node = (SvOK($arg) ? (char *)SvPV($arg,PL_na) : NULL);
	char *	service = (SvOK($arg) ? (char *)SvPV($arg,PL_na) : NULL);
	SV *	hints_ref = (SvOK($arg) ? $arg : NULL);
	CODE:
	{
	struct addrinfo hints;
	struct addrinfo *hints_ptr = NULL;
	struct val_addrinfo *vainfo_ptr = NULL;
	int res;

	hints_ptr = ainfo_sv2c(hints_ref, &hints);

	res = val_getaddrinfo(ctx, node, service, hints_ptr, &vainfo_ptr);

	if (res == 0) {
	  RETVAL = ainfo_c2sv(vainfo_ptr);
	} else {
	  RETVAL = newSViv(res);
	}

	val_freeaddrinfo(vainfo_ptr);
	}
	OUTPUT:
	RETVAL



char *
pval_gai_strerror(err)
	int err
	CODE:
	{
	  RETVAL = (char*)gai_strerror(err);
	}
	OUTPUT:
	RETVAL

int
pval_gethostbyname(ctx=NULL,name="localhost")
	ValContext * ctx = (SvROK($arg) ? (ValContext*)SvIV((SV*)SvRV($arg)) : NULL);
	char *	name
	CODE:
	{
	struct hostent  hentry;
	char	    buf[PVAL_BUFSIZE];
	char	    str_buf[PVAL_BUFSIZE];
	struct hostent *result = NULL;
	int             herrno = 0;
	val_status_t    val_status;
	int		i, res;

	bzero(&hentry, sizeof(struct hostent));
	bzero(buf, PVAL_BUFSIZE);

	res = val_gethostbyname_r(ctx, name, &hentry, buf, PVAL_BUFSIZE,
                                      &result, &herrno, &val_status);

	RETVAL = res = (result == NULL ? -1 : 0);
	
	if (result != NULL) {
	  fprintf(stderr,"\n\th_name = %s\n", result->h_name);
	  if (result->h_aliases) {
            fprintf(stderr,"\th_aliases = \n");
            for (i = 0; result->h_aliases[i] != 0; i++) {
	      fprintf(stderr,"\t\t[%d] = %s\n", i, result->h_aliases[i]);
            }
	  } else
            fprintf(stderr,"\th_aliases = NULL\n");
	  if (result->h_addrtype == AF_INET) {
            fprintf(stderr,"\th_addrtype = AF_INET\n");
	  } else if (result->h_addrtype == AF_INET6) {
            fprintf(stderr,"\th_addrtype = AF_INET6\n");
	  } else {
            fprintf(stderr,"\th_addrtype = %d\n", result->h_addrtype);
	  }
	  fprintf(stderr,"\th_length = %d\n", result->h_length);
	  fprintf(stderr,"\th_addr_list = \n");
	  for (i = 0; result->h_addr_list[i] != 0; i++) {
            bzero(str_buf, INET6_ADDRSTRLEN);
            fprintf(stderr,"\t\t[%d] = %s\n", i,
		    inet_ntop(result->h_addrtype,
			      result->h_addr_list[i],
			      str_buf, INET6_ADDRSTRLEN));
	  }
	} else {
	  RETVAL = val_status;
	}
	}
	OUTPUT:
	RETVAL

SV *
pval_res_query(ctx=NULL,dname,class,type)
	ValContext * ctx = (SvROK($arg) ? (ValContext*)SvIV((SV*)SvRV($arg)) : NULL);
	char *	dname
	int	class
	int	type
	CODE:
	{
	int res;
	unsigned char buf[PVAL_BUFSIZE];
	val_status_t val_status;

	bzero(buf, PVAL_BUFSIZE);
	res = val_res_query(ctx, dname, class, type, buf, PVAL_BUFSIZE,
                            &val_status);
	if (res == -1) {
	  res = sprintf(buf,"%s(%d)",p_val_error(val_status),val_status);
	}
	RETVAL = newSVpvn(buf,res);
	}
	OUTPUT:
	RETVAL

const char *
pval_ac_status(err)
	int err
	CODE:
	{
	  RETVAL = p_ac_status(err);
	}
	OUTPUT:
	RETVAL

const char *
pval_val_status(err)
	int err
	CODE:
	{
	  RETVAL = p_val_status(err);
	}
	OUTPUT:
	RETVAL

int
pval_istrusted(err)
	int err
	CODE:
	{
	  RETVAL = val_istrusted(err);
	}
	OUTPUT:
	RETVAL

MODULE = Net::DNS::SEC::Validator PACKAGE = ValContextPtr PREFIX = vc_

void
vc_DESTROY(vc_ptr)
	ValContext *vc_ptr
	CODE:
	{
	  val_free_context( vc_ptr );
	}




