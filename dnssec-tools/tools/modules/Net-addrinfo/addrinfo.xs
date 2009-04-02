/* -*- C -*-
     addrinfo.xs -- Perl 5 interface to getaddrinfo(3) and related structs

     written by G. S. Marzot (marz@users.sourceforge.net)

     Copyright (c) 2006 G. S. Marzot. All rights reserved.

     Copyright (c) 2006-2008 SPARTA, Inc.  All rights reserved.

     This program is free software; you can redistribute it and/or
     modify it under the same terms as Perl itself.
*/

#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

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

#ifndef na
#define na PL_na
#endif

#ifndef sv_undef
#define sv_undef PL_sv_undef
#endif

#define ADDRINFO_TYPE     0
#define VAL_ADDRINFO_TYPE 1

typedef struct addrinfo AddrInfo;

#if 0
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
  if (ainfo_ref && SvROK(ainfo_ref) && ainfo_ptr) {
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
      ainfo_ptr->ai_addr = (struct sockaddr *) SvPV(*addr_svp,na); // borrowed
      ainfo_ptr->ai_addrlen = SvLEN(*addr_svp); // ignore hash field addrlen?
    } else {
      ainfo_ptr->ai_addr = NULL;
      ainfo_ptr->ai_addrlen = 0;
    }
    ainfo_ptr->ai_canonname = (SvOK(*canonname_svp) ? 
			       SvPV(*canonname_svp,na) : NULL); // borrowed

    // fprintf(stderr, "ainfo_ptr->ai_flags = %d\n", ainfo_ptr->ai_flags);
    // fprintf(stderr, "ainfo_ptr->ai_family = %d\n", ainfo_ptr->ai_family);
    // fprintf(stderr, "ainfo_ptr->ai_socktype = %d\n", ainfo_ptr->ai_socktype);
    // fprintf(stderr, "ainfo_ptr->ai_protocol = %d\n", ainfo_ptr->ai_protocol);
    // fprintf(stderr, "ainfo_ptr->ai_addrlen = %d\n", ainfo_ptr->ai_addrlen);
    // fprintf(stderr,"ainfo_ptr->ai_canonname=%s\n",ainfo_ptr->ai_canonname);
  } else {
    return NULL;
  }
  return ainfo_ptr;
}

SV *ainfo_c2sv(struct addrinfo *ainfo_ptr)
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
    (void)hv_store(ainfo_hv, "flags", strlen("flags"), 
	     newSViv(ainfo_ptr->ai_flags), 0);
    (void)hv_store(ainfo_hv, "family", strlen("family"), 
	     newSViv(ainfo_ptr->ai_family), 0);
    (void)hv_store(ainfo_hv, "socktype", strlen("socktype"), 
	     newSViv(ainfo_ptr->ai_socktype), 0);
    (void)hv_store(ainfo_hv, "protocol", strlen("protocol"), 
	     newSViv(ainfo_ptr->ai_protocol), 0);
    (void)hv_store(ainfo_hv, "addr", strlen("addr"), 
	     newSVpv((char*)ainfo_ptr->ai_addr, 
		     ainfo_ptr->ai_addrlen), 0);
    (void)hv_store(ainfo_hv, "addrlen", strlen("addrlen"), 
	     newSViv(ainfo_ptr->ai_addrlen), 0);
    (void)hv_store(ainfo_hv, "canonname", strlen("canonname"), 
	     (ainfo_ptr->ai_canonname ?
	      newSVpv(ainfo_ptr->ai_canonname, 
		      strlen(ainfo_ptr->ai_canonname)) :
	     &sv_undef), 0);

    av_push(ainfo_av, ainfo_hv_ref);
  }  
  return ainfo_av_ref;
}

#include "const-c.inc"

MODULE = Net::addrinfo	PACKAGE = Net::addrinfo	PREFIX = addrinfo

INCLUDE: const-xs.inc

SV *
addrinfo_getaddrinfo(node=NULL,service=NULL,hints_ref=NULL)
        char *	node = (SvOK($arg) ? (char *)SvPV($arg,PL_na) : NULL);
	char *	service = (SvOK($arg) ? (char *)SvPV($arg,PL_na) : NULL);
	SV *	hints_ref = (SvOK($arg) ? $arg : NULL);
	CODE:
	{
	struct addrinfo hints;
	struct addrinfo *hints_ptr = NULL;
	struct addrinfo *ainfo_ptr = NULL;
	int res;

	hints_ptr = ainfo_sv2c(hints_ref, &hints);

	res = getaddrinfo(node, service, hints_ptr, &ainfo_ptr);

	if (res == 0) {
	  RETVAL = ainfo_c2sv(ainfo_ptr);
	} else {
	  RETVAL = newSViv(res);
	}

	freeaddrinfo(ainfo_ptr);
	}
	OUTPUT:
	RETVAL

char *
addrinfo_gai_strerror(err)
	int err
	CODE:
	{
	  RETVAL = (char*)gai_strerror(err);
	}
	OUTPUT:
	RETVAL

MODULE = Net::addrinfo	PACKAGE = AddrInfoPtr	PREFIX = addr_info_

void
addr_info_DESTROY(addrinfo_ptr)
	AddrInfo *addrinfo_ptr
	CODE:
	{
	  freeaddrinfo( addrinfo_ptr );
	}

