/* -*- C -*-
     Validator.xs -- Perl 5 interface to the Dnssec-Tools validating resolver

     written by G. S. Marzot (marz@users.sourceforge.net)

     Copyright (c) 2006-2008 SPARTA, Inc.  All rights reserved.

     Copyright (c) 2006-2007 G. S. Marzot. All rights reserved.

     This program is free software; you can redistribute it and/or
     modify it under the same terms as Perl itself.
*/
#include "EXTERN.h"
#include "perl.h"
#include "XSUB.h"

#include "validator/validator-config.h"
#include "validator/resolver.h"
#include "validator/validator.h"

#define PVAL_BUFSIZE	(16*1024)
#define ADDRINFO_TYPE		0
#define VAL_ADDRINFO_TYPE	1

typedef struct libval_context ValContext;
typedef struct val_global_opt ValContextGlOpt;
typedef struct val_context_opt ValContextOpt;

typedef struct val_cb_params_s ValCBParams;
typedef struct val_async_status_s ValAsyncStatus;

struct _pval_async_cbdata {
    SV *cb;
    SV *cb_data;
};


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
	ainfo_ptr->ai_addr = (struct sockaddr *) SvPV_nolen(*addr_svp); // borrowed
	ainfo_ptr->ai_addrlen = SvLEN(*addr_svp);
      } else {
	ainfo_ptr->ai_addr = NULL;
	ainfo_ptr->ai_addrlen = 0;
      }
      ainfo_ptr->ai_canonname = (SvOK(*canonname_svp) ? 
				 SvPV_nolen(*canonname_svp) : NULL); // borrowed

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

SV *rr_c2sv(char *name, int type, int class, long ttl, size_t len, u_char *data)
{
  dSP ;

  SV *rr = &PL_sv_undef;

  ENTER ;
  SAVETMPS;

  PUSHMARK(SP);
  XPUSHs(sv_2mortal(newSVpv("Net::DNS::RR", 0))) ;
  XPUSHs(sv_2mortal(newSVpv((char*)name, 0))) ;
  XPUSHs(sv_2mortal(newSVpv(p_sres_type(type), 0))) ;
  XPUSHs(sv_2mortal(newSVpv(p_class(class), 0))) ;
  XPUSHs(sv_2mortal(newSVnv(ttl))) ;
  XPUSHs(sv_2mortal(newSViv(len))) ;
  XPUSHs(sv_2mortal(newRV(sv_2mortal(newSVpvn((char*)data, len))))) ;
  PUTBACK;

  call_method("new_from_data", G_SCALAR|G_EVAL);
  if (SvTRUE(ERRSV)) {
    /* Try the decode function */
    u_char *buf = NULL;
    size_t buflen = 0;

    if(VAL_NO_ERROR != 
          val_create_rr_otw(name, type, class, ttl, 
                len, data, &buflen, &buf)) {
        goto err;
    }

    POPs; // remove the undef value from the top of the stack

    SPAGAIN ;
    PUSHMARK(SP);
    XPUSHs(sv_2mortal(newSVpv("Net::DNS::RR", 0))) ;
    XPUSHs(sv_2mortal(newRV(sv_2mortal(newSVpvn((char*)buf, buflen))))) ;
    PUTBACK;
    call_method("decode", G_SCALAR);

    free(buf);
  }

  SPAGAIN ;
  rr = newSVsv(POPs);
  PUTBACK ;

err:
  FREETMPS ;
  LEAVE ;

  return rr;
}

SV *rrset_c2sv(struct val_rrset_rec *rrs_ptr)
{
  HV *rrset_hv = newHV();
  SV *rrset_hv_ref = newRV_noinc((SV*)rrset_hv);
  AV *rrs_avd = newAV();
  SV *rrs_avd_ref = newRV_noinc((SV*)rrs_avd);
  AV *rrs_avs = newAV();
  SV *rrs_avs_ref = newRV_noinc((SV*)rrs_avs);
  HV *rr_hv;
  SV *rr_hv_ref;
  struct val_rr_rec *rr;
  char name_buf[INET6_ADDRSTRLEN + 1];

  if (rrs_ptr) {

    (void)hv_store(rrset_hv, "name", strlen("name"), 
	          newSVpv(rrs_ptr->val_rrset_name, 
                   strlen(rrs_ptr->val_rrset_name)), 0);

    (void)hv_store(rrset_hv, "class", strlen("class"),
              newSVpv(p_class(rrs_ptr->val_rrset_class), 0), 0);

    (void)hv_store(rrset_hv, "type", strlen("type"),
              newSVpv(p_sres_type(rrs_ptr->val_rrset_type), 0), 0);

    (void)hv_store(rrset_hv, "ttl", strlen("ttl"),
              newSVnv(rrs_ptr->val_rrset_ttl),0);

    for (rr = rrs_ptr->val_rrset_data; rr; rr = rr->rr_next) {
      rr_hv = newHV();
      rr_hv_ref = newRV_noinc((SV*)rr_hv);

      (void)hv_store(rr_hv, "rrdata", strlen("rrdata"), 
	      rr_c2sv(rrs_ptr->val_rrset_name,
		      rrs_ptr->val_rrset_type,
		      rrs_ptr->val_rrset_class,
	          rrs_ptr->val_rrset_ttl,
		      rr->rr_rdata_length,
		      rr->rr_rdata), 0);

      (void)hv_store(rr_hv, "rrstatus", strlen("rrstatus"),
              newSViv(rr->rr_status),0);

      av_push(rrs_avd, rr_hv_ref);
    }

    (void)hv_store(rrset_hv, "data", strlen("data"), rrs_avd_ref, 0);

    for (rr = rrs_ptr->val_rrset_sig; rr; rr = rr->rr_next) {
      rr_hv = newHV();
      rr_hv_ref = newRV_noinc((SV*)rr_hv);

      (void)hv_store(rr_hv, "rrdata", strlen("rrdata"), 
	      rr_c2sv(rrs_ptr->val_rrset_name,
		      ns_t_rrsig,
		      rrs_ptr->val_rrset_class,
		      rrs_ptr->val_rrset_ttl,
		      rr->rr_rdata_length,
		      rr->rr_rdata), 0);

      (void)hv_store(rr_hv, "rrstatus", strlen("rrstatus"),
              newSViv(rr->rr_status),0);

      av_push(rrs_avs, rr_hv_ref);
    }

    (void)hv_store(rrset_hv, "sigs", strlen("sigs"), rrs_avs_ref, 0);

    val_get_ns_string(rrs_ptr->val_rrset_server, 
            name_buf, sizeof(name_buf));

    (void)hv_store(rrset_hv, "respserv", strlen("respserv"), 
	               newSVpv(name_buf, strlen(name_buf)), 0);
  }

  return rrset_hv_ref;
}

SV *ac_c2sv(struct val_authentication_chain *ac_ptr)
{
  AV *ac_av = newAV();
  SV *ac_av_ref = newRV_noinc((SV*)ac_av);

  struct val_authentication_chain *t;

  t = ac_ptr;
  while(t) {

    HV *ac_hv = newHV();
    SV *ac_hv_ref = newRV_noinc((SV*)ac_hv);

    (void)hv_store(ac_hv, "status", strlen("status"), 
	     newSViv(t->val_ac_status), 0);

    (void)hv_store(ac_hv, "rrset", strlen("rrset"), 
	     rrset_c2sv(t->val_ac_rrset), 0);

    av_push(ac_av, ac_hv_ref);

    t = t->val_ac_trust;
  }

  return ac_av_ref;
}

SV *rc_c2sv(struct val_result_chain *rc_ptr)
{
  int i;
  AV *rc_av = newAV();
  SV *rc_av_ref = newRV_noinc((SV*)rc_av);
  HV *result_hv;
  SV *result_hv_ref;
  AV *proofs_av;
  SV *proofs_av_ref;

  while (rc_ptr) {
    result_hv = newHV();
    result_hv_ref = newRV_noinc((SV*)result_hv);

    (void)hv_store(result_hv, "status", strlen("status"), 
	     newSViv(rc_ptr->val_rc_status), 0);

    /* fprintf(stderr, "rc status == %d\n", rc_ptr->val_rc_status); XXX */
    
    if (rc_ptr->val_rc_answer != NULL) {
        (void)hv_store(result_hv, "answer", strlen("answer"), 
	        ac_c2sv(rc_ptr->val_rc_answer), 0);
    } 
    else {
        (void)hv_store(result_hv, "rrset", strlen("rrset"),
            rrset_c2sv(rc_ptr->val_rc_rrset), 0);
    }

    proofs_av = newAV();
    proofs_av_ref = newRV_noinc((SV*)proofs_av);
  
    for(i=0; i < rc_ptr->val_rc_proof_count && 
	  rc_ptr->val_rc_proof_count < MAX_PROOFS; i++) {
      av_push(proofs_av, ac_c2sv(rc_ptr->val_rc_proofs[i]));
    }

    (void)hv_store(result_hv, "proofs", strlen("proofs"), proofs_av_ref, 0);

    av_push(rc_av, result_hv_ref);  

    rc_ptr = rc_ptr->val_rc_next;
  }


  return rc_av_ref;
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
    (void)hv_store(ainfo_hv, "canonname", strlen("canonname"), 
	     (ainfo_ptr->ai_canonname ?
	      newSVpv(ainfo_ptr->ai_canonname, 
		      strlen(ainfo_ptr->ai_canonname)) :
	     &PL_sv_undef), 0);

    av_push(ainfo_av, ainfo_hv_ref);
  }  
  return ainfo_av_ref;
}


SV *hostent_c2sv(struct hostent *hent_ptr)
{
  AV *hent_av;
  SV *hent_av_ref;
  AV *hent_aliases_av;
  SV *hent_aliases_av_ref;
  AV *hent_addrs_av;
  SV *hent_addrs_av_ref;
  int i;

  if (hent_ptr == NULL) return &PL_sv_undef;
  
  hent_av = newAV();
  hent_av_ref = newRV_noinc((SV*)hent_av);
  

  sv_bless(hent_av_ref, gv_stashpv("Net::hostent",0));

  av_push(hent_av, newSVpv(hent_ptr->h_name,0));

  hent_aliases_av = newAV();
  hent_aliases_av_ref = newRV_noinc((SV*)hent_aliases_av);

  av_push(hent_av, hent_aliases_av_ref);

  if (hent_ptr->h_aliases) {
    for (i = 0; hent_ptr->h_aliases[i] != 0; i++) {
      av_push(hent_aliases_av, newSVpv(hent_ptr->h_aliases[i],0));
    }
  }

  av_push(hent_av, newSViv(hent_ptr->h_addrtype));

  av_push(hent_av, newSViv(hent_ptr->h_length));

  hent_addrs_av = newAV();
  hent_addrs_av_ref = newRV_noinc((SV*)hent_addrs_av);

  av_push(hent_av, hent_addrs_av_ref);

  for (i = 0; hent_ptr->h_addr_list[i] != 0; i++) {
    av_push(hent_addrs_av, newSVpvn(hent_ptr->h_addr_list[i],
				    hent_ptr->h_length));
  }

  return hent_av_ref;
}

int
_pval_async_cb(ValAsyncStatus *as, int event,
               ValContext *ctx, void *callback_data,
               ValCBParams *cbp) 
{
    dSP;
    SV *res = &PL_sv_undef;
    int ret = -1;

    struct _pval_async_cbdata *cbd = 
        (struct _pval_async_cbdata *)callback_data;

    if (cbp && cbp->results) { 
        ret = cbp->retval;
        res = rc_c2sv(cbp->results);
        val_free_result_chain(cbp->results);
        cbp->results = NULL;
    }

    ENTER ;
    SAVETMPS;

    PUSHMARK(SP);
    XPUSHs(cbd->cb_data);
    XPUSHs(sv_2mortal(newSViv(ret)));
    XPUSHs(res);
    PUTBACK;

    call_sv(cbd->cb, G_DISCARD);

    FREETMPS ;
    LEAVE ;

    SvREFCNT_dec(res);
    SvREFCNT_dec(cbd->cb_data);
    SvREFCNT_dec(cbd->cb);
    free(cbd);

    return 0;
}


#include "const-c.inc"

MODULE = Net::DNS::SEC::Validator	PACKAGE = Net::DNS::SEC::Validator	PREFIX = pval

INCLUDE: const-xs.inc

ValContext *
pval_create_context(policy)
	char * policy
	CODE:
	{
	ValContext *vc_ptr=NULL;

	int result = val_create_context(policy, &vc_ptr);

	RETVAL = (result ? NULL : vc_ptr);
	}
	OUTPUT:
	RETVAL

ValContext *
pval_create_context_with_conf(policy,dnsval_conf,resolv_conf,root_hints)
	char * policy = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
        char *	dnsval_conf = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
	char *	resolv_conf = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
	char *	root_hints = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
	CODE:
	{
	ValContext *vc_ptr=NULL;
	//	fprintf(stderr,"pval_create_context_with_conf:%s:%s:%s\n",dnsval_conf,resolv_conf,root_hints);

	//val_log_add_optarg("7:stderr", 1); /* XXX */

	int result = val_create_context_with_conf(policy, 
						  dnsval_conf,
						  resolv_conf,
						  root_hints,
						  &vc_ptr);
	//	fprintf(stderr,"pval_create_context_with_confresult=%d):%lx\n",result,vc_ptr);

	RETVAL = (result ? NULL : vc_ptr);
	}
	OUTPUT:
	RETVAL

ValContext *
pval_create_context_ex(optref)
	SV * optref = (SvOK($arg) ? $arg : NULL);
	CODE:
	{
	ValContext *vc_ptr=NULL;
    ValContextOpt opt;
    ValContextGlOpt gopt;
    char *label;


    // Find the policy label
    SV **label_svp = hv_fetch((HV*)SvRV(optref), "policy", 6, 1);
    label = (SvOK(*label_svp) ? SvPV_nolen(*label_svp) : ":");

    // Context options
    SV **vc_qflags_svp = hv_fetch((HV*)SvRV(optref), "qflags", 6, 1);
    opt.vc_qflags = (SvOK(*vc_qflags_svp) ? SvIV(*vc_qflags_svp) : 0);
    SV **vc_valpol_svp = hv_fetch((HV*)SvRV(optref), "valpol", 6, 1);
    opt.vc_valpol = (SvOK(*vc_valpol_svp) ? SvPV_nolen(*vc_valpol_svp) : NULL);
    SV **vc_nslist_svp = hv_fetch((HV*)SvRV(optref), "nslist", 6, 1);
    opt.vc_nslist = (SvOK(*vc_nslist_svp) ? SvPV_nolen(*vc_nslist_svp) : NULL);
    SV **dnsval_conf_svp = hv_fetch((HV*)SvRV(optref), "dnsval_conf", 11, 1);
    opt.vc_val_conf = (SvOK(*dnsval_conf_svp) ?  SvPV_nolen(*dnsval_conf_svp) : NULL);
    SV **resolv_conf_svp = hv_fetch((HV*)SvRV(optref), "resolv_conf", 11, 1);
    opt.vc_res_conf = (SvOK(*resolv_conf_svp) ?  SvPV_nolen(*resolv_conf_svp) : NULL);
    SV **root_conf_svp = hv_fetch((HV*)SvRV(optref), "root_hints", 10, 1);
    opt.vc_root_conf = (SvOK(*root_conf_svp) ?  SvPV_nolen(*root_conf_svp) : NULL);

    // Set the policy override flags to override resolver information,
    // but only if it was defined
    SV **vc_polflags_svp = hv_fetch((HV*)SvRV(optref), "polflags", 8, 1);
    if (SvOK(*vc_polflags_svp)) {
        opt.vc_polflags = SvIV(*vc_polflags_svp);
    } else if (opt.vc_nslist != NULL) {
        opt.vc_polflags = CTX_DYN_POL_RES_OVR;
    } else {
        opt.vc_polflags = 0;
    }

    // Global options
    SV **local_is_trusted_svp = hv_fetch((HV*)SvRV(optref), "local_is_trusted", 16, 1);
    gopt.local_is_trusted = (SvOK(*local_is_trusted_svp) ?
            SvIV(*local_is_trusted_svp) : VAL_POL_GOPT_UNSET);
    SV **edns0_size_svp = hv_fetch((HV*)SvRV(optref), "edns0_size", 10, 1);
    gopt.edns0_size = (SvOK(*edns0_size_svp) ? SvIV(*edns0_size_svp) :
            VAL_POL_GOPT_UNSET);
    SV **env_policy_svp = hv_fetch((HV*)SvRV(optref), "env_policy", 10, 1);
    gopt.env_policy = (SvOK(*env_policy_svp) ? SvIV(*env_policy_svp) :
            VAL_POL_GOPT_UNSET);
    SV **app_policy_svp = hv_fetch((HV*)SvRV(optref), "app_policy", 10, 1);
    gopt.app_policy = (SvOK(*app_policy_svp) ? SvIV(*app_policy_svp) :
            VAL_POL_GOPT_UNSET);
    SV **log_target_svp = hv_fetch((HV*)SvRV(optref), "log_target", 10, 1);
    gopt.log_target = (SvOK(*log_target_svp) ? SvPV_nolen(*log_target_svp) : NULL);
    SV **closest_ta_only_svp = hv_fetch((HV*)SvRV(optref), "closest_ta_only", 15, 1);
    gopt.closest_ta_only = (SvOK(*closest_ta_only_svp) ?
            SvIV(*closest_ta_only_svp) : VAL_POL_GOPT_UNSET);
    SV **rec_fallback_svp = hv_fetch((HV*)SvRV(optref), "rec_fallback", 12, 1);
    gopt.rec_fallback = (SvOK(*rec_fallback_svp) ?
            SvIV(*rec_fallback_svp) : VAL_POL_GOPT_UNSET);
    SV **max_refresh_svp = hv_fetch((HV*)SvRV(optref), "max_refresh", 11, 1);
    gopt.max_refresh = (SvOK(*max_refresh_svp) ?
            (long)SvIV(*max_refresh_svp) : VAL_POL_GOPT_UNSET);
    SV **proto_svp = hv_fetch((HV*)SvRV(optref), "proto", 5, 1);
    gopt.proto = (SvOK(*proto_svp) ?
            SvIV(*proto_svp) : VAL_POL_GOPT_UNSET);

    opt.vc_gopt = &gopt;

	int result = val_create_context_ex(label, 
                          &opt,
						  &vc_ptr);
	//	fprintf(stderr,"pval_create_context_with_confresult=%d):%lx\n",result,vc_ptr);

	RETVAL = (result ? NULL : vc_ptr);
	}
	OUTPUT:
	RETVAL


SV *
pval_getaddrinfo(self,node=NULL,service=NULL,hints_ref=NULL)
	SV *	self
        char *	node = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
	char *	service = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
	SV *	hints_ref = (SvOK($arg) ? $arg : NULL);
	CODE:
	{
	ValContext *		ctx;
	SV **			ctx_ref;
	SV **			error_svp;
        SV **			error_str_svp;
        SV **			val_status_svp;
	SV **			val_status_str_svp;
	struct addrinfo		hints;
	struct addrinfo *	hints_ptr = NULL;
	struct addrinfo *	ainfo_ptr = NULL;
	val_status_t            val_status;
	int res;

	ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
	ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

	error_svp = hv_fetch((HV*)SvRV(self), "error", 5, 1);
        error_str_svp = hv_fetch((HV*)SvRV(self), "errorStr", 8, 1);
	val_status_svp = hv_fetch((HV*)SvRV(self), "valStatus", 9, 1);
        val_status_str_svp = hv_fetch((HV*)SvRV(self), "valStatusStr", 12, 1);
        
        sv_setiv(*error_svp, 0);
        sv_setpv(*error_str_svp, "");
        sv_setiv(*val_status_svp, 0);
        sv_setpv(*val_status_str_svp, "");

	hints_ptr = ainfo_sv2c(hints_ref, &hints);

	res = val_getaddrinfo(ctx, node, service, hints_ptr, 
			      &ainfo_ptr, &val_status);

	if (res == 0) {
      if (val_getaddrinfo_has_status(res)) {
	    sv_setiv(*val_status_svp, val_status);
	    sv_setpv(*val_status_str_svp, p_val_status(val_status));
      }
	  RETVAL = ainfo_c2sv(ainfo_ptr);
	} else {
	  sv_setiv(*error_svp, res);
	  sv_setpv(*error_str_svp, gai_strerror(res));
	  RETVAL = &PL_sv_undef;
	}

	freeaddrinfo(ainfo_ptr);
	}
	OUTPUT:
	RETVAL


SV *
pval_gethostbyname(self,name,af=AF_INET)
	SV *	self
	char *	name = (SvOK($arg) ? (char *)SvPV_nolen($arg) : "localhost");
	int	af = (SvOK($arg) ? SvIV($arg) : AF_INET);
	CODE:
	{
	ValContext     *ctx;
	SV **		ctx_ref;
	SV **		error_svp;
        SV **		error_str_svp;
        SV **		val_status_svp;
	SV **		val_status_str_svp;
	char	        buf[PVAL_BUFSIZE];
	struct hostent *result = NULL;
	struct hostent  hentry;
	int             herrno = 0;
	val_status_t    val_status;
	int		res;

	bzero(&hentry, sizeof(struct hostent));
	bzero(buf, PVAL_BUFSIZE);

	ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
	ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

	error_svp = hv_fetch((HV*)SvRV(self), "error", 5, 1);
        error_str_svp = hv_fetch((HV*)SvRV(self), "errorStr", 8, 1);
	val_status_svp = hv_fetch((HV*)SvRV(self), "valStatus", 9, 1);
        val_status_str_svp = hv_fetch((HV*)SvRV(self), "valStatusStr", 12, 1);
        
        sv_setiv(*error_svp, 0);
        sv_setpv(*error_str_svp, "");
        sv_setiv(*val_status_svp, 0);
        sv_setpv(*val_status_str_svp, "");

	res = val_gethostbyname2_r(ctx, name, af, &hentry, buf, PVAL_BUFSIZE,
				  &result, &herrno, &val_status);

	sv_setiv(*val_status_svp, val_status);
	sv_setpv(*val_status_str_svp, p_val_status(val_status));

	if (res) {
	   RETVAL = &PL_sv_undef;
	   sv_setiv(*error_svp, herrno);
	   sv_setpv(*error_str_svp, hstrerror(herrno));
	} else {
	   RETVAL = hostent_c2sv(result);
	}
	}
	OUTPUT:
	RETVAL

SV *
pval_res_query(self,dname,class,type)
	SV *	self
	char *	dname
	int	class
	int	type
	CODE:
	{
	ValContext     *ctx;
	SV **		error_svp;
        SV **		error_str_svp;
        SV **		val_status_svp;
	SV **		val_status_str_svp;
	SV **		ctx_ref;
	int		res;
	unsigned char	buf[PVAL_BUFSIZE];
	val_status_t	val_status;

	bzero(buf, PVAL_BUFSIZE);

	ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
	ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

	error_svp = hv_fetch((HV*)SvRV(self), "error", 5, 1);
        error_str_svp = hv_fetch((HV*)SvRV(self), "errorStr", 8, 1);
	val_status_svp = hv_fetch((HV*)SvRV(self), "valStatus", 9, 1);
        val_status_str_svp = hv_fetch((HV*)SvRV(self), "valStatusStr", 12, 1);
        
        sv_setiv(*error_svp, 0);
        sv_setpv(*error_str_svp, "");
        sv_setiv(*val_status_svp, 0);
        sv_setpv(*val_status_str_svp, "");
	
	//  fprintf(stderr,"before:%p:%s:%d:%d:%d:%d\n",ctx,dname,class,type,res,val_status);

	res = val_res_query(ctx, dname, class, type, buf, PVAL_BUFSIZE,
                            &val_status);

	//  fprintf(stderr,"after:%p:%s:%d:%d:%d:%d:%d:%s\n",ctx,dname,class,type,res,val_status,h_errno,hstrerror(h_errno));
        
	sv_setiv(*val_status_svp, val_status);
        sv_setpv(*val_status_str_svp, p_val_status(val_status));

	if (res == -1) {
	  RETVAL = &PL_sv_undef;
	  sv_setiv(*error_svp, h_errno); // this is not thread safe
          sv_setpv(*error_str_svp, hstrerror(h_errno));
	} else {
	  RETVAL =newSVpvn((char*)buf, res);
	}
	}
	OUTPUT:
	RETVAL


SV *
pval_resolve_and_check(self,domain,class,type,flags)
	SV * self
	char * domain
        int class
        int type
        int flags
	CODE:
	{
	ValContext *		ctx;
	SV **			ctx_ref;
	SV **			error_svp;
        SV **			error_str_svp;
        SV **			val_status_svp;
	SV **			val_status_str_svp;
	struct val_result_chain * val_rc_ptr = NULL;
	int res;
	//fprintf(stderr, "here we are at the start\n");

	ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
	ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

	error_svp = hv_fetch((HV*)SvRV(self), "error", 5, 1);
        error_str_svp = hv_fetch((HV*)SvRV(self), "errorStr", 8, 1);
	val_status_svp = hv_fetch((HV*)SvRV(self), "valStatus", 9, 1);
        val_status_str_svp = hv_fetch((HV*)SvRV(self), "valStatusStr", 12, 1);
        
        sv_setiv(*error_svp, 0);
        sv_setpv(*error_str_svp, "");
        sv_setiv(*val_status_svp, 0);
        sv_setpv(*val_status_str_svp, "");

	RETVAL = &PL_sv_undef;
	//fprintf(stderr, "here we are way before\n");

	  //fprintf(stderr, "here we are before\n");
	  res = val_resolve_and_check(ctx, domain, 
				      class, 
				      type, 
				      (u_int32_t) flags, 
				      &val_rc_ptr);
	  //fprintf(stderr, "here we are after\n");
	  val_log_authentication_chain(ctx, LOG_DEBUG,
				       domain, 
				       class, 
				       type, 
				       val_rc_ptr);
	  if (res == 0) {
	    RETVAL = rc_c2sv(val_rc_ptr);
	  } else {
	    sv_setiv(*error_svp, res);
	    sv_setpv(*error_str_svp, p_val_err(res));
	  }

	  val_free_result_chain(val_rc_ptr);
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

const char *
pval_val_error(err)
	int err
	CODE:
	{
	  RETVAL = p_val_err(err);
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


int
pval_isvalidated(err)
	int err
	CODE:
	{
	  RETVAL = val_isvalidated(err);
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

char *
pval_resolv_conf_get()
	CODE:
	{
	  RETVAL = resolv_conf_get();
	}
	OUTPUT:
	RETVAL

int
pval_resolv_conf_set(file)
	char *file
	CODE:
	{
	  RETVAL = resolv_conf_set(file);
	}
	OUTPUT:
	RETVAL

char *
pval_root_hints_get()
	CODE:
	{
	  RETVAL = root_hints_get();
	}
	OUTPUT:
	RETVAL

int
pval_root_hints_set(file)
	char *file
	CODE:
	{
	  RETVAL = root_hints_set(file);
	}
	OUTPUT:
	RETVAL

char *
pval_dnsval_conf_get()
	CODE:
	{
	  RETVAL = dnsval_conf_get();
	}
	OUTPUT:
	RETVAL

int
pval_dnsval_conf_set(file)
	char *file
	CODE:
	{
	  RETVAL = dnsval_conf_set(file);
	}
	OUTPUT:
	RETVAL

SV * 
pval_async_submit(self,domain,class,type,flags, cbref, cbparam)
    SV * self
    char *domain = (SvOK($arg) ? (char *)SvPV_nolen($arg) : NULL);
    int class
    int type
    int flags
    SV *cbref = (SvOK($arg) ? $arg : NULL);
    SV *cbparam = (SvOK($arg) ? $arg : NULL);
    CODE:
    {
        SV **ctx_ref;
        ValContext *ctx;
        int ret;
        int inflight = 0;
        ValAsyncStatus *vas = NULL;
        AV * results = newAV();

        struct _pval_async_cbdata *cbd =
            (struct _pval_async_cbdata *)malloc(sizeof(struct _pval_async_cbdata));

        ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
        ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

        cbd->cb = newSVsv(cbref);
        cbd->cb_data = newSVsv(cbparam);

        ret = val_async_submit(ctx, domain, class, type, flags,
                         _pval_async_cb, cbd,
                         &vas);
        inflight = (val_async_getflags(vas) & VAL_AS_INFLIGHT)?  1 : 0;

        av_push(results, newSViv(ret));
        av_push(results, newSViv(inflight));
        RETVAL = newRV_noinc((SV *)results);
    }
    OUTPUT:
    RETVAL


SV * 
pval_async_gather(self,active,timeout)
    SV* self
    SV* active
    int timeout = (SvOK($arg) ? SvIV($arg):10);
    INIT:
    CODE:
    {
        SV **ctx_ref;
        AV *active_arr;
        AV *updated;
        SV *fd_cur = NULL;
        ValContext *ctx;
        int ret;
        fd_set  activefds;
        struct timeval tv;
        int nfds = -1;
        int fd;
        int i;
        AV * results = newAV();

        tv.tv_sec = timeout; 
        tv.tv_usec = 0;

        FD_ZERO(&activefds);

        ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
        ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

        // Update list of sockets that are ready for current validator
        // context
        ret = val_async_select_info(ctx, &activefds, &nfds, &tv);

        // Initialize the descriptors that are already set
        if ((SvROK(active)) && (SvTYPE(SvRV(active)) == SVt_PVAV)) {
            active_arr = (AV*) SvRV(active);
            while (av_len(active_arr) >= 0) {
                fd_cur = (SV*)av_shift((AV*)active_arr);
                fd = SvIV(fd_cur);
                FD_SET(fd, &activefds);
                nfds = (fd > nfds)? fd : nfds; 
            }
        }

        updated = newAV();

        for (i = 0 ; i <= nfds ; i++) {
            if (FD_ISSET(i, &activefds)) {
                fd_cur = newSViv(i);
                av_push(updated, fd_cur);
            }
        }
        av_push(results, newSViv(ret));
        av_push(results, newRV_noinc((SV*) updated));
        av_push(results, newSVnv(tv.tv_sec + tv.tv_usec/1000000));

        RETVAL = newRV_noinc((SV *)results);
    }
    OUTPUT:
    RETVAL

SV * 
pval_async_check(self,active)
    SV* self
    SV* active
    CODE:
    {
        SV **ctx_ref;
        AV *active_arr;
        SV *fd_cur = NULL;
        AV *updated;
        ValContext *ctx;
        int ret;
        fd_set  activefds;
        int nfds = 0;
        int fd;
        int i;
        AV * results = newAV();

        FD_ZERO(&activefds);

        // Initialize the descriptors that are already set
        if ((SvROK(active)) && (SvTYPE(SvRV(active)) == SVt_PVAV)) {

            active_arr = (AV*) SvRV(active);
            while (av_len(active_arr) >= 0) {
                fd_cur = (SV*)av_shift((AV*)active_arr);
                fd = SvIV(fd_cur);
                FD_SET(fd, &activefds);
                nfds = (fd > nfds)? fd : nfds; 
            }
        }

        ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
        ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

        //ret = val_async_check(ctx, &activefds, &nfds, 0);
        ret = val_async_check_wait(ctx, &activefds, &nfds, NULL, 0);

        updated = newAV();

        for (i = 0 ; i <= nfds ; i++) {
            if (FD_ISSET(i, &activefds)) {
                fd_cur = newSViv(i);
                av_push(updated, fd_cur);
            }
        }

        av_push(results, newSViv(ret));
        av_push(results, newRV_noinc((SV*) updated));
        RETVAL = newRV_noinc((SV *)results);
    }
    OUTPUT:
    RETVAL


int 
pval_async_gather_check_wait(self,timeout)
    SV * self
    int timeout = (SvOK($arg) ? SvIV($arg) : 10);
    CODE:
    {
        SV **ctx_ref;
        ValContext *ctx;
        int ret;
        fd_set  activefds;
        int nfds = 0;
        struct timeval tv;

        tv.tv_sec = timeout; 
        tv.tv_usec = 0;

        ctx_ref = hv_fetch((HV*)SvRV(self), "_ctx_ptr", 8, 1);
        ctx = (ValContext *)SvIV((SV*)SvRV(*ctx_ref));

        FD_ZERO(&activefds);

        //ret = val_async_check_wait(ctx, NULL, NULL, &tv);
        val_async_select_info(ctx, &activefds, &nfds, &tv);
        ret = select(nfds+1, &activefds, NULL, NULL, &tv);
        if (ret >= 0) {
            ret = val_async_check(ctx, &activefds, &nfds, 0);
        }

        RETVAL = ret;
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
      vc_ptr = NULL;
	}
