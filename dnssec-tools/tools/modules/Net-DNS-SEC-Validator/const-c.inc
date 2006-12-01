#define PERL_constant_NOTFOUND	1
#define PERL_constant_NOTDEF	2
#define PERL_constant_ISIV	3
#define PERL_constant_ISNO	4
#define PERL_constant_ISNV	5
#define PERL_constant_ISPV	6
#define PERL_constant_ISPVN	7
#define PERL_constant_ISSV	8
#define PERL_constant_ISUNDEF	9
#define PERL_constant_ISUV	10
#define PERL_constant_ISYES	11

#ifndef NVTYPE
typedef double NV; /* 5.6 and later define NVTYPE, and typedef NV to it.  */
#endif
#ifndef aTHX_
#define aTHX_ /* 5.6 or later define this for threading support.  */
#endif
#ifndef pTHX_
#define pTHX_ /* 5.6 or later define this for threading support.  */
#endif

static int
constant_6 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_DH Q_INIT Q_SENT SIGNBY */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'B':
    if (memEQ(name, "SIGNBY", 6)) {
    /*                   ^       */
#ifdef SIGNBY
      *iv_return = SIGNBY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "ALG_DH", 6)) {
    /*                   ^       */
#ifdef ALG_DH
      *iv_return = ALG_DH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "Q_INIT", 6)) {
    /*                   ^       */
#ifdef Q_INIT
      *iv_return = Q_INIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "Q_SENT", 6)) {
    /*                   ^       */
#ifdef Q_SENT
      *iv_return = Q_SENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_8 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     DNS_PORT SR_UNSET */
  /* Offset 6 gives the best switch position.  */
  switch (name[6]) {
  case 'E':
    if (memEQ(name, "SR_UNSET", 8)) {
    /*                     ^       */
#ifdef SR_UNSET
      *iv_return = SR_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "DNS_PORT", 8)) {
    /*                     ^       */
#ifdef DNS_PORT
      *iv_return = DNS_PORT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_9 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     RES_RETRY VAL_BOGUS VAL_ERROR ns_t_nsec */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'R':
    if (memEQ(name, "VAL_ERRO", 8)) {
    /*                       R     */
#ifdef VAL_ERROR
      *iv_return = VAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_BOGU", 8)) {
    /*                       S     */
#ifdef VAL_BOGUS
      *iv_return = VAL_BOGUS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "RES_RETR", 8)) {
    /*                       Y     */
#ifdef RES_RETRY
      *iv_return = RES_RETRY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'c':
    if (memEQ(name, "ns_t_nse", 8)) {
    /*                       c     */
#ifdef ns_t_nsec
      *iv_return = ns_t_nsec;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_10 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_RSAMD5 NS_INT16SZ NS_INT32SZ Q_ANSWERED RRSIGLABEL
     SR_FORMERR SR_NOTIMPL SR_REFUSED ns_t_nsec3 ns_t_rrsig */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case '2':
    if (memEQ(name, "NS_INT32SZ", 10)) {
    /*                      ^         */
#ifdef NS_INT32SZ
      *iv_return = NS_INT32SZ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '6':
    if (memEQ(name, "NS_INT16SZ", 10)) {
    /*                      ^         */
#ifdef NS_INT16SZ
      *iv_return = NS_INT16SZ;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "RRSIGLABEL", 10)) {
    /*                      ^         */
#ifdef RRSIGLABEL
      *iv_return = RRSIGLABEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_FORMERR", 10)) {
    /*                      ^         */
#ifdef SR_FORMERR
      *iv_return = SR_FORMERR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "ALG_RSAMD5", 10)) {
    /*                      ^         */
#ifdef ALG_RSAMD5
      *iv_return = ALG_RSAMD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_NOTIMPL", 10)) {
    /*                      ^         */
#ifdef SR_NOTIMPL
      *iv_return = SR_NOTIMPL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "Q_ANSWERED", 10)) {
    /*                      ^         */
#ifdef Q_ANSWERED
      *iv_return = Q_ANSWERED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_REFUSED", 10)) {
    /*                      ^         */
#ifdef SR_REFUSED
      *iv_return = SR_REFUSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'e':
    if (memEQ(name, "ns_t_nsec3", 10)) {
    /*                      ^         */
#ifdef ns_t_nsec3
      *iv_return = ns_t_nsec3;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 's':
    if (memEQ(name, "ns_t_rrsig", 10)) {
    /*                      ^         */
#ifdef ns_t_rrsig
      *iv_return = ns_t_rrsig;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_11 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_DSASHA1 ALG_RSASHA1 NS_MAXDNAME SR_NXDOMAIN SR_SERVFAIL VAL_AC_INIT
     VAL_NOTRUST VAL_SUCCESS ns_t_dnskey */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'C':
    if (memEQ(name, "VAL_AC_INIT", 11)) {
    /*                    ^            */
#ifdef VAL_AC_INIT
      *iv_return = VAL_AC_INIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SR_NXDOMAIN", 11)) {
    /*                    ^            */
#ifdef SR_NXDOMAIN
      *iv_return = SR_NXDOMAIN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_NOTRUST", 11)) {
    /*                    ^            */
#ifdef VAL_NOTRUST
      *iv_return = VAL_NOTRUST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SR_SERVFAIL", 11)) {
    /*                    ^            */
#ifdef SR_SERVFAIL
      *iv_return = SR_SERVFAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "ALG_DSASHA1", 11)) {
    /*                    ^            */
#ifdef ALG_DSASHA1
      *iv_return = ALG_DSASHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "ALG_RSASHA1", 11)) {
    /*                    ^            */
#ifdef ALG_RSASHA1
      *iv_return = ALG_RSASHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_SUCCESS", 11)) {
    /*                    ^            */
#ifdef VAL_SUCCESS
      *iv_return = VAL_SUCCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "NS_MAXDNAME", 11)) {
    /*                    ^            */
#ifdef NS_MAXDNAME
      *iv_return = NS_MAXDNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'd':
    if (memEQ(name, "ns_t_dnskey", 11)) {
    /*                    ^            */
#ifdef ns_t_dnskey
      *iv_return = ns_t_dnskey;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_12 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CAN_SIGN_KEY NS_CMPRSFLGS NS_MAXCDNAME Q_ERROR_BASE SR_ANS_CNAME
     SR_ANS_DNAME SR_ANS_UNSET SR_CRED_FILE SR_NO_ANSWER VAL_AC_UNSET
     VAL_NO_ERROR */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'C':
    if (memEQ(name, "VAL_AC_UNSET", 12)) {
    /*                    ^             */
#ifdef VAL_AC_UNSET
      *iv_return = VAL_AC_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_CRED_FILE", 12)) {
    /*                    ^             */
#ifdef SR_CRED_FILE
      *iv_return = SR_CRED_FILE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "CAN_SIGN_KEY", 12)) {
    /*                    ^             */
#ifdef CAN_SIGN_KEY
      *iv_return = CAN_SIGN_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "Q_ERROR_BASE", 12)) {
    /*                    ^             */
#ifdef Q_ERROR_BASE
      *iv_return = Q_ERROR_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_NO_ERROR", 12)) {
    /*                    ^             */
#ifdef VAL_NO_ERROR
      *iv_return = VAL_NO_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "NS_CMPRSFLGS", 12)) {
    /*                    ^             */
#ifdef NS_CMPRSFLGS
      *iv_return = NS_CMPRSFLGS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_ANS_CNAME", 12)) {
    /*                    ^             */
#ifdef SR_ANS_CNAME
      *iv_return = SR_ANS_CNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_ANS_DNAME", 12)) {
    /*                    ^             */
#ifdef SR_ANS_DNAME
      *iv_return = SR_ANS_DNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_ANS_UNSET", 12)) {
    /*                    ^             */
#ifdef SR_ANS_UNSET
      *iv_return = SR_ANS_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "NS_MAXCDNAME", 12)) {
    /*                    ^             */
#ifdef NS_MAXCDNAME
      *iv_return = NS_MAXCDNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SR_NO_ANSWER", 12)) {
    /*                    ^             */
#ifdef SR_NO_ANSWER
      *iv_return = SR_NO_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_13 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CAN_SIGN_ZONE EDNS_UDP_SIZE SR_CALL_ERROR SR_CRED_UNSET SR_LAST_ERROR
     SR_TSIG_ERROR VAL_CTX_IDLEN VAL_DONT_KNOW VAL_NO_POLICY ZONE_USE_TSIG
   */
  /* Offset 6 gives the best switch position.  */
  switch (name[6]) {
  case 'D':
    if (memEQ(name, "EDNS_UDP_SIZE", 13)) {
    /*                     ^             */
#ifdef EDNS_UDP_SIZE
      *iv_return = EDNS_UDP_SIZE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_CRED_UNSET", 13)) {
    /*                     ^             */
#ifdef SR_CRED_UNSET
      *iv_return = SR_CRED_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "CAN_SIGN_ZONE", 13)) {
    /*                     ^             */
#ifdef CAN_SIGN_ZONE
      *iv_return = CAN_SIGN_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_TSIG_ERROR", 13)) {
    /*                     ^             */
#ifdef SR_TSIG_ERROR
      *iv_return = SR_TSIG_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SR_CALL_ERROR", 13)) {
    /*                     ^             */
#ifdef SR_CALL_ERROR
      *iv_return = SR_CALL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_DONT_KNOW", 13)) {
    /*                     ^             */
#ifdef VAL_DONT_KNOW
      *iv_return = VAL_DONT_KNOW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "ZONE_USE_TSIG", 13)) {
    /*                     ^             */
#ifdef ZONE_USE_TSIG
      *iv_return = ZONE_USE_TSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SR_LAST_ERROR", 13)) {
    /*                     ^             */
#ifdef SR_LAST_ERROR
      *iv_return = SR_LAST_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "VAL_CTX_IDLEN", 13)) {
    /*                     ^             */
#ifdef VAL_CTX_IDLEN
      *iv_return = VAL_CTX_IDLEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_NO_POLICY", 13)) {
    /*                     ^             */
#ifdef VAL_NO_POLICY
      *iv_return = VAL_NO_POLICY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_14 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CANNOT_BE_USED RES_USE_DNSSEC VAL_BARE_RRSIG VAL_FROM_QUERY VAL_FROM_UNSET
  */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'N':
    if (memEQ(name, "RES_USE_DNSSEC", 14)) {
    /*                        ^           */
#ifdef RES_USE_DNSSEC
      *iv_return = RES_USE_DNSSEC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Q':
    if (memEQ(name, "VAL_FROM_QUERY", 14)) {
    /*                        ^           */
#ifdef VAL_FROM_QUERY
      *iv_return = VAL_FROM_QUERY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_BARE_RRSIG", 14)) {
    /*                        ^           */
#ifdef VAL_BARE_RRSIG
      *iv_return = VAL_BARE_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_FROM_UNSET", 14)) {
    /*                        ^           */
#ifdef VAL_FROM_UNSET
      *iv_return = VAL_FROM_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "CANNOT_BE_USED", 14)) {
    /*                        ^           */
#ifdef CANNOT_BE_USED
      *iv_return = CANNOT_BE_USED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_15 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     Q_WAIT_FOR_GLUE SR_ANS_NACK_SOA SR_ANS_STRAIGHT SR_MEMORY_ERROR
     SR_MISSING_GLUE SR_WRONG_ANSWER VAL_AC_BAD_BASE VAL_AC_LAST_BAD
     VAL_AC_VERIFIED VAL_BOGUS_PROOF VAL_FROM_ANSWER VAL_LOG_OPTIONS */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'B':
    if (memEQ(name, "VAL_AC_BAD_BASE", 15)) {
    /*                      ^              */
#ifdef VAL_AC_BAD_BASE
      *iv_return = VAL_AC_BAD_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "Q_WAIT_FOR_GLUE", 15)) {
    /*                      ^              */
#ifdef Q_WAIT_FOR_GLUE
      *iv_return = Q_WAIT_FOR_GLUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "SR_WRONG_ANSWER", 15)) {
    /*                      ^              */
#ifdef SR_WRONG_ANSWER
      *iv_return = SR_WRONG_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SR_MISSING_GLUE", 15)) {
    /*                      ^              */
#ifdef SR_MISSING_GLUE
      *iv_return = SR_MISSING_GLUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_AC_LAST_BAD", 15)) {
    /*                      ^              */
#ifdef VAL_AC_LAST_BAD
      *iv_return = VAL_AC_LAST_BAD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "VAL_FROM_ANSWER", 15)) {
    /*                      ^              */
#ifdef VAL_FROM_ANSWER
      *iv_return = VAL_FROM_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SR_ANS_NACK_SOA", 15)) {
    /*                      ^              */
#ifdef SR_ANS_NACK_SOA
      *iv_return = SR_ANS_NACK_SOA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SR_MEMORY_ERROR", 15)) {
    /*                      ^              */
#ifdef SR_MEMORY_ERROR
      *iv_return = SR_MEMORY_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_ANS_STRAIGHT", 15)) {
    /*                      ^              */
#ifdef SR_ANS_STRAIGHT
      *iv_return = SR_ANS_STRAIGHT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_BOGUS_PROOF", 15)) {
    /*                      ^              */
#ifdef VAL_BOGUS_PROOF
      *iv_return = VAL_BOGUS_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "VAL_AC_VERIFIED", 15)) {
    /*                      ^              */
#ifdef VAL_AC_VERIFIED
      *iv_return = VAL_AC_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_LOG_OPTIONS", 15)) {
    /*                      ^              */
#ifdef VAL_LOG_OPTIONS
      *iv_return = VAL_LOG_OPTIONS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_DS_HASH_SHA1 SR_ANS_NACK_NSEC SR_CRED_AUTH_ADD SR_CRED_AUTH_ANS
     SR_NO_ANSWER_YET VAL_AC_FAIL_BASE VAL_AC_TRUST_KEY VAL_BAD_ARGUMENT
     VAL_LOCAL_ANSWER VAL_TRUSTED_ZONE ZONE_USE_NOTHING */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
  case 'A':
    if (memEQ(name, "VAL_LOCAL_ANSWER", 16)) {
    /*                         ^            */
#ifdef VAL_LOCAL_ANSWER
      *iv_return = VAL_LOCAL_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_TRUSTED_ZONE", 16)) {
    /*                         ^            */
#ifdef VAL_TRUSTED_ZONE
      *iv_return = VAL_TRUSTED_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_NO_ANSWER_YET", 16)) {
    /*                         ^            */
#ifdef SR_NO_ANSWER_YET
      *iv_return = SR_NO_ANSWER_YET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "VAL_BAD_ARGUMENT", 16)) {
    /*                         ^            */
#ifdef VAL_BAD_ARGUMENT
      *iv_return = VAL_BAD_ARGUMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "ALG_DS_HASH_SHA1", 16)) {
    /*                         ^            */
#ifdef ALG_DS_HASH_SHA1
      *iv_return = ALG_DS_HASH_SHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "SR_ANS_NACK_NSEC", 16)) {
    /*                         ^            */
#ifdef SR_ANS_NACK_NSEC
      *iv_return = SR_ANS_NACK_NSEC;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_AC_FAIL_BASE", 16)) {
    /*                         ^            */
#ifdef VAL_AC_FAIL_BASE
      *iv_return = VAL_AC_FAIL_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "ZONE_USE_NOTHING", 16)) {
    /*                         ^            */
#ifdef ZONE_USE_NOTHING
      *iv_return = ZONE_USE_NOTHING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_AC_TRUST_KEY", 16)) {
    /*                         ^            */
#ifdef VAL_AC_TRUST_KEY
      *iv_return = VAL_AC_TRUST_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SR_CRED_AUTH_ADD", 16)) {
    /*                         ^            */
#ifdef SR_CRED_AUTH_ADD
      *iv_return = SR_CRED_AUTH_ADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_CRED_AUTH_ANS", 16)) {
    /*                         ^            */
#ifdef SR_CRED_AUTH_ANS
      *iv_return = SR_CRED_AUTH_ANS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_17 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_NSEC3_DSASHA1 ALG_NSEC3_RSASHA1 SHA_DIGEST_LENGTH SIG_ACCEPT_WINDOW
     SR_ANS_BARE_RRSIG SR_ANS_NACK_NSEC3 SR_CRED_AUTH_AUTH SR_HEADER_BADSIZE
     SR_INTERNAL_ERROR SR_REFERRAL_ERROR VAL_AC_BARE_RRSIG VAL_AC_CAN_VERIFY
     VAL_AC_DS_MISSING VAL_AC_ERROR_BASE VAL_AC_LAST_ERROR VAL_AC_LAST_STATE
     VAL_FLAGS_DEFAULT VAL_INDETERMINATE VAL_NO_PERMISSION VAL_OUT_OF_MEMORY
     free_val_addrinfo */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
  case 'B':
    if (memEQ(name, "SR_HEADER_BADSIZE", 17)) {
    /*                         ^             */
#ifdef SR_HEADER_BADSIZE
      *iv_return = SR_HEADER_BADSIZE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "ALG_NSEC3_DSASHA1", 17)) {
    /*                         ^             */
#ifdef ALG_NSEC3_DSASHA1
      *iv_return = ALG_NSEC3_DSASHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_FLAGS_DEFAULT", 17)) {
    /*                         ^             */
#ifdef VAL_FLAGS_DEFAULT
      *iv_return = VAL_FLAGS_DEFAULT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_ANS_BARE_RRSIG", 17)) {
    /*                         ^             */
#ifdef SR_ANS_BARE_RRSIG
      *iv_return = SR_ANS_BARE_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_BARE_RRSIG", 17)) {
    /*                         ^             */
#ifdef VAL_AC_BARE_RRSIG
      *iv_return = VAL_AC_BARE_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "SR_ANS_NACK_NSEC3", 17)) {
    /*                         ^             */
#ifdef SR_ANS_NACK_NSEC3
      *iv_return = SR_ANS_NACK_NSEC3;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SR_INTERNAL_ERROR", 17)) {
    /*                         ^             */
#ifdef SR_INTERNAL_ERROR
      *iv_return = SR_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_REFERRAL_ERROR", 17)) {
    /*                         ^             */
#ifdef SR_REFERRAL_ERROR
      *iv_return = SR_REFERRAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "VAL_AC_DS_MISSING", 17)) {
    /*                         ^             */
#ifdef VAL_AC_DS_MISSING
      *iv_return = VAL_AC_DS_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_NO_PERMISSION", 17)) {
    /*                         ^             */
#ifdef VAL_NO_PERMISSION
      *iv_return = VAL_NO_PERMISSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_AC_ERROR_BASE", 17)) {
    /*                         ^             */
#ifdef VAL_AC_ERROR_BASE
      *iv_return = VAL_AC_ERROR_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "ALG_NSEC3_RSASHA1", 17)) {
    /*                         ^             */
#ifdef ALG_NSEC3_RSASHA1
      *iv_return = ALG_NSEC3_RSASHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_INDETERMINATE", 17)) {
    /*                         ^             */
#ifdef VAL_INDETERMINATE
      *iv_return = VAL_INDETERMINATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SR_CRED_AUTH_AUTH", 17)) {
    /*                         ^             */
#ifdef SR_CRED_AUTH_AUTH
      *iv_return = SR_CRED_AUTH_AUTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_LAST_ERROR", 17)) {
    /*                         ^             */
#ifdef VAL_AC_LAST_ERROR
      *iv_return = VAL_AC_LAST_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_LAST_STATE", 17)) {
    /*                         ^             */
#ifdef VAL_AC_LAST_STATE
      *iv_return = VAL_AC_LAST_STATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "SHA_DIGEST_LENGTH", 17)) {
    /*                         ^             */
#ifdef SHA_DIGEST_LENGTH
      *iv_return = SHA_DIGEST_LENGTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SIG_ACCEPT_WINDOW", 17)) {
    /*                         ^             */
#ifdef SIG_ACCEPT_WINDOW
      *iv_return = SIG_ACCEPT_WINDOW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_CAN_VERIFY", 17)) {
    /*                         ^             */
#ifdef VAL_AC_CAN_VERIFY
      *iv_return = VAL_AC_CAN_VERIFY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_OUT_OF_MEMORY", 17)) {
    /*                         ^             */
#ifdef VAL_OUT_OF_MEMORY
      *iv_return = VAL_OUT_OF_MEMORY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_NSEC_HASH_SHA1 SR_ZI_STATUS_UNSET VALIDATOR_LOG_PORT
     VAL_AC_INVALID_KEY VAL_AC_SIGNING_KEY VAL_BOGUS_PROVABLE
     VAL_CONF_NOT_FOUND VAL_DNS_ERROR_BASE VAL_DNS_ERROR_LAST
     VAL_FROM_AUTHORITY VAL_INTERNAL_ERROR VAL_UNTRUSTED_ZONE
     VAL_VERIFIED_CHAIN */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'C':
    if (memEQ(name, "ALG_NSEC_HASH_SHA1", 18)) {
    /*                      ^                 */
#ifdef ALG_NSEC_HASH_SHA1
      *iv_return = ALG_NSEC_HASH_SHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_INTERNAL_ERROR", 18)) {
    /*                      ^                 */
#ifdef VAL_INTERNAL_ERROR
      *iv_return = VAL_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "VAL_CONF_NOT_FOUND", 18)) {
    /*                      ^                 */
#ifdef VAL_CONF_NOT_FOUND
      *iv_return = VAL_CONF_NOT_FOUND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "VAL_AC_INVALID_KEY", 18)) {
    /*                      ^                 */
#ifdef VAL_AC_INVALID_KEY
      *iv_return = VAL_AC_INVALID_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_VERIFIED_CHAIN", 18)) {
    /*                      ^                 */
#ifdef VAL_VERIFIED_CHAIN
      *iv_return = VAL_VERIFIED_CHAIN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "VAL_FROM_AUTHORITY", 18)) {
    /*                      ^                 */
#ifdef VAL_FROM_AUTHORITY
      *iv_return = VAL_FROM_AUTHORITY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VALIDATOR_LOG_PORT", 18)) {
    /*                      ^                 */
#ifdef VALIDATOR_LOG_PORT
      *iv_return = VALIDATOR_LOG_PORT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_UNTRUSTED_ZONE", 18)) {
    /*                      ^                 */
#ifdef VAL_UNTRUSTED_ZONE
      *iv_return = VAL_UNTRUSTED_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_AC_SIGNING_KEY", 18)) {
    /*                      ^                 */
#ifdef VAL_AC_SIGNING_KEY
      *iv_return = VAL_AC_SIGNING_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SR_ZI_STATUS_UNSET", 18)) {
    /*                      ^                 */
#ifdef SR_ZI_STATUS_UNSET
      *iv_return = SR_ZI_STATUS_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_BOGUS_PROVABLE", 18)) {
    /*                      ^                 */
#ifdef VAL_BOGUS_PROVABLE
      *iv_return = VAL_BOGUS_PROVABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_DNS_ERROR_BASE", 18)) {
    /*                      ^                 */
#ifdef VAL_DNS_ERROR_BASE
      *iv_return = VAL_DNS_ERROR_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_DNS_ERROR_LAST", 18)) {
    /*                      ^                 */
#ifdef VAL_DNS_ERROR_LAST
      *iv_return = VAL_DNS_ERROR_LAST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_NSEC3_HASH_SHA1 SR_CRED_NONAUTH_ADD SR_CRED_NONAUTH_ANS
     VAL_AC_DATA_MISSING VAL_AC_LAST_FAILURE VAL_AC_LOCAL_ANSWER
     VAL_AC_NOT_VERIFIED VAL_AC_TRUSTED_ZONE VAL_DONT_GO_FURTHER
     VAL_FROM_ADDITIONAL VAL_NOT_IMPLEMENTED */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'A':
    if (memEQ(name, "VAL_FROM_ADDITIONAL", 19)) {
    /*                        ^                */
#ifdef VAL_FROM_ADDITIONAL
      *iv_return = VAL_FROM_ADDITIONAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "VAL_AC_LOCAL_ANSWER", 19)) {
    /*                        ^                */
#ifdef VAL_AC_LOCAL_ANSWER
      *iv_return = VAL_AC_LOCAL_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "VAL_DONT_GO_FURTHER", 19)) {
    /*                        ^                */
#ifdef VAL_DONT_GO_FURTHER
      *iv_return = VAL_DONT_GO_FURTHER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "VAL_NOT_IMPLEMENTED", 19)) {
    /*                        ^                */
#ifdef VAL_NOT_IMPLEMENTED
      *iv_return = VAL_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SR_CRED_NONAUTH_ADD", 19)) {
    /*                        ^                */
#ifdef SR_CRED_NONAUTH_ADD
      *iv_return = SR_CRED_NONAUTH_ADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_CRED_NONAUTH_ANS", 19)) {
    /*                        ^                */
#ifdef SR_CRED_NONAUTH_ANS
      *iv_return = SR_CRED_NONAUTH_ANS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_AC_LAST_FAILURE", 19)) {
    /*                        ^                */
#ifdef VAL_AC_LAST_FAILURE
      *iv_return = VAL_AC_LAST_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_AC_DATA_MISSING", 19)) {
    /*                        ^                */
#ifdef VAL_AC_DATA_MISSING
      *iv_return = VAL_AC_DATA_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_NOT_VERIFIED", 19)) {
    /*                        ^                */
#ifdef VAL_AC_NOT_VERIFIED
      *iv_return = VAL_AC_NOT_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_AC_TRUSTED_ZONE", 19)) {
    /*                        ^                */
#ifdef VAL_AC_TRUSTED_ZONE
      *iv_return = VAL_AC_TRUSTED_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "ALG_NSEC3_HASH_SHA1", 19)) {
    /*                        ^                */
#ifdef ALG_NSEC3_HASH_SHA1
      *iv_return = ALG_NSEC3_HASH_SHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_20 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SR_CRED_NONAUTH_AUTH SR_DNS_GENERIC_ERROR SR_ZI_STATUS_LEARNED
     VAL_AC_INVALID_RRSIG VAL_AC_KEY_TOO_LARGE VAL_AC_KEY_TOO_SMALL
     VAL_AC_RRSIG_EXPIRED VAL_AC_RRSIG_MISSING VAL_AC_VERIFIED_LINK
     VAL_BOGUS_UNPROVABLE VAL_CONF_PARSE_ERROR VAL_INCOMPLETE_PROOF
     VAL_INDETERMINATE_DS VAL_IRRELEVANT_PROOF VAL_NONEXISTENT_NAME
     VAL_NONEXISTENT_TYPE */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'E':
    if (memEQ(name, "VAL_INDETERMINATE_DS", 20)) {
    /*                        ^                 */
#ifdef VAL_INDETERMINATE_DS
      *iv_return = VAL_INDETERMINATE_DS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_IRRELEVANT_PROOF", 20)) {
    /*                        ^                 */
#ifdef VAL_IRRELEVANT_PROOF
      *iv_return = VAL_IRRELEVANT_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "VAL_NONEXISTENT_NAME", 20)) {
    /*                        ^                 */
#ifdef VAL_NONEXISTENT_NAME
      *iv_return = VAL_NONEXISTENT_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_NONEXISTENT_TYPE", 20)) {
    /*                        ^                 */
#ifdef VAL_NONEXISTENT_TYPE
      *iv_return = VAL_NONEXISTENT_TYPE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SR_DNS_GENERIC_ERROR", 20)) {
    /*                        ^                 */
#ifdef SR_DNS_GENERIC_ERROR
      *iv_return = SR_DNS_GENERIC_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SR_CRED_NONAUTH_AUTH", 20)) {
    /*                        ^                 */
#ifdef SR_CRED_NONAUTH_AUTH
      *iv_return = SR_CRED_NONAUTH_AUTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_CONF_PARSE_ERROR", 20)) {
    /*                        ^                 */
#ifdef VAL_CONF_PARSE_ERROR
      *iv_return = VAL_CONF_PARSE_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_INCOMPLETE_PROOF", 20)) {
    /*                        ^                 */
#ifdef VAL_INCOMPLETE_PROOF
      *iv_return = VAL_INCOMPLETE_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_VERIFIED_LINK", 20)) {
    /*                        ^                 */
#ifdef VAL_AC_VERIFIED_LINK
      *iv_return = VAL_AC_VERIFIED_LINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_AC_RRSIG_EXPIRED", 20)) {
    /*                        ^                 */
#ifdef VAL_AC_RRSIG_EXPIRED
      *iv_return = VAL_AC_RRSIG_EXPIRED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_RRSIG_MISSING", 20)) {
    /*                        ^                 */
#ifdef VAL_AC_RRSIG_MISSING
      *iv_return = VAL_AC_RRSIG_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "SR_ZI_STATUS_LEARNED", 20)) {
    /*                        ^                 */
#ifdef SR_ZI_STATUS_LEARNED
      *iv_return = SR_ZI_STATUS_LEARNED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "VAL_AC_INVALID_RRSIG", 20)) {
    /*                        ^                 */
#ifdef VAL_AC_INVALID_RRSIG
      *iv_return = VAL_AC_INVALID_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "VAL_AC_KEY_TOO_LARGE", 20)) {
    /*                        ^                 */
#ifdef VAL_AC_KEY_TOO_LARGE
      *iv_return = VAL_AC_KEY_TOO_LARGE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_KEY_TOO_SMALL", 20)) {
    /*                        ^                 */
#ifdef VAL_AC_KEY_TOO_SMALL
      *iv_return = VAL_AC_KEY_TOO_SMALL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_BOGUS_UNPROVABLE", 20)) {
    /*                        ^                 */
#ifdef VAL_BOGUS_UNPROVABLE
      *iv_return = VAL_BOGUS_UNPROVABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_21 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     CAN_SIGN_ZONE_AND_KEY SR_EDNS_VERSION_ERROR SR_RCV_INTERNAL_ERROR
     SR_UNSUPP_EDNS0_LABEL VAL_AC_BAD_DELEGATION VAL_AC_DNSKEY_MISSING
     VAL_AC_DNSKEY_NOMATCH VAL_AC_DNS_ERROR_BASE VAL_AC_DNS_ERROR_LAST
     VAL_AC_NEGATIVE_PROOF VAL_AC_RRSIG_VERIFIED VAL_AC_UNTRUSTED_ZONE
     VAL_AC_WAIT_FOR_RRSIG VAL_AC_WAIT_FOR_TRUST VAL_AC_WCARD_VERIFIED
     VAL_IGNORE_VALIDATION VAL_PROVABLY_UNSECURE */
  /* Offset 16 gives the best switch position.  */
  switch (name[16]) {
  case 'A':
    if (memEQ(name, "VAL_AC_BAD_DELEGATION", 21)) {
    /*                               ^           */
#ifdef VAL_AC_BAD_DELEGATION
      *iv_return = VAL_AC_BAD_DELEGATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_IGNORE_VALIDATION", 21)) {
    /*                               ^           */
#ifdef VAL_IGNORE_VALIDATION
      *iv_return = VAL_IGNORE_VALIDATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "CAN_SIGN_ZONE_AND_KEY", 21)) {
    /*                               ^           */
#ifdef CAN_SIGN_ZONE_AND_KEY
      *iv_return = CAN_SIGN_ZONE_AND_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_EDNS_VERSION_ERROR", 21)) {
    /*                               ^           */
#ifdef SR_EDNS_VERSION_ERROR
      *iv_return = SR_EDNS_VERSION_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_RCV_INTERNAL_ERROR", 21)) {
    /*                               ^           */
#ifdef SR_RCV_INTERNAL_ERROR
      *iv_return = SR_RCV_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_PROVABLY_UNSECURE", 21)) {
    /*                               ^           */
#ifdef VAL_PROVABLY_UNSECURE
      *iv_return = VAL_PROVABLY_UNSECURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "VAL_AC_RRSIG_VERIFIED", 21)) {
    /*                               ^           */
#ifdef VAL_AC_RRSIG_VERIFIED
      *iv_return = VAL_AC_RRSIG_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_WCARD_VERIFIED", 21)) {
    /*                               ^           */
#ifdef VAL_AC_WCARD_VERIFIED
      *iv_return = VAL_AC_WCARD_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SR_UNSUPP_EDNS0_LABEL", 21)) {
    /*                               ^           */
#ifdef SR_UNSUPP_EDNS0_LABEL
      *iv_return = SR_UNSUPP_EDNS0_LABEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "VAL_AC_DNSKEY_NOMATCH", 21)) {
    /*                               ^           */
#ifdef VAL_AC_DNSKEY_NOMATCH
      *iv_return = VAL_AC_DNSKEY_NOMATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_AC_NEGATIVE_PROOF", 21)) {
    /*                               ^           */
#ifdef VAL_AC_NEGATIVE_PROOF
      *iv_return = VAL_AC_NEGATIVE_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_WAIT_FOR_RRSIG", 21)) {
    /*                               ^           */
#ifdef VAL_AC_WAIT_FOR_RRSIG
      *iv_return = VAL_AC_WAIT_FOR_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_AC_DNSKEY_MISSING", 21)) {
    /*                               ^           */
#ifdef VAL_AC_DNSKEY_MISSING
      *iv_return = VAL_AC_DNSKEY_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_AC_WAIT_FOR_TRUST", 21)) {
    /*                               ^           */
#ifdef VAL_AC_WAIT_FOR_TRUST
      *iv_return = VAL_AC_WAIT_FOR_TRUST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_AC_DNS_ERROR_BASE", 21)) {
    /*                               ^           */
#ifdef VAL_AC_DNS_ERROR_BASE
      *iv_return = VAL_AC_DNS_ERROR_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_DNS_ERROR_LAST", 21)) {
    /*                               ^           */
#ifdef VAL_AC_DNS_ERROR_LAST
      *iv_return = VAL_AC_DNS_ERROR_LAST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_UNTRUSTED_ZONE", 21)) {
    /*                               ^           */
#ifdef VAL_AC_UNTRUSTED_ZONE
      *iv_return = VAL_AC_UNTRUSTED_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_22 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     MAX_ALIAS_CHAIN_LENGTH SR_CONFLICTING_ANSWERS SR_SEND_INTERNAL_ERROR
     SR_TSIG_INTERNAL_ERROR SR_ZI_STATUS_PERMANENT VAL_AC_DONT_GO_FURTHER
     VAL_AC_NO_TRUST_ANCHOR VAL_QUERY_MERGE_RRSETS */
  /* Offset 6 gives the best switch position.  */
  switch (name[6]) {
  case 'D':
    if (memEQ(name, "SR_SEND_INTERNAL_ERROR", 22)) {
    /*                     ^                      */
#ifdef SR_SEND_INTERNAL_ERROR
      *iv_return = SR_SEND_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_QUERY_MERGE_RRSETS", 22)) {
    /*                     ^                      */
#ifdef VAL_QUERY_MERGE_RRSETS
      *iv_return = VAL_QUERY_MERGE_RRSETS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "SR_CONFLICTING_ANSWERS", 22)) {
    /*                     ^                      */
#ifdef SR_CONFLICTING_ANSWERS
      *iv_return = SR_CONFLICTING_ANSWERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "SR_TSIG_INTERNAL_ERROR", 22)) {
    /*                     ^                      */
#ifdef SR_TSIG_INTERNAL_ERROR
      *iv_return = SR_TSIG_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "MAX_ALIAS_CHAIN_LENGTH", 22)) {
    /*                     ^                      */
#ifdef MAX_ALIAS_CHAIN_LENGTH
      *iv_return = MAX_ALIAS_CHAIN_LENGTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_ZI_STATUS_PERMANENT", 22)) {
    /*                     ^                      */
#ifdef SR_ZI_STATUS_PERMANENT
      *iv_return = SR_ZI_STATUS_PERMANENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_AC_DONT_GO_FURTHER", 22)) {
    /*                     ^                      */
#ifdef VAL_AC_DONT_GO_FURTHER
      *iv_return = VAL_AC_DONT_GO_FURTHER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_NO_TRUST_ANCHOR", 22)) {
    /*                     ^                      */
#ifdef VAL_AC_NO_TRUST_ANCHOR
      *iv_return = VAL_AC_NO_TRUST_ANCHOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_23 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     VAL_FLAGS_DONT_VALIDATE VAL_FLAG_CHAIN_COMPLETE VAL_INDETERMINATE_PROOF */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'S':
    if (memEQ(name, "VAL_FLAGS_DONT_VALIDATE", 23)) {
    /*                       ^                     */
#ifdef VAL_FLAGS_DONT_VALIDATE
      *iv_return = VAL_FLAGS_DONT_VALIDATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_INDETERMINATE_PROOF", 23)) {
    /*                       ^                     */
#ifdef VAL_INDETERMINATE_PROOF
      *iv_return = VAL_INDETERMINATE_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_FLAG_CHAIN_COMPLETE", 23)) {
    /*                       ^                     */
#ifdef VAL_FLAG_CHAIN_COMPLETE
      *iv_return = VAL_FLAG_CHAIN_COMPLETE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_24 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     VAL_AC_ALGORITHM_REFUSED VAL_AC_IGNORE_VALIDATION VAL_AC_PROVABLY_UNSECURE
     VAL_AC_UNKNOWN_ALGORITHM VAL_AC_WRONG_LABEL_COUNT VAL_RESOURCE_UNAVAILABLE
     */
  /* Offset 22 gives the best switch position.  */
  switch (name[22]) {
  case 'E':
    if (memEQ(name, "VAL_AC_ALGORITHM_REFUSED", 24)) {
    /*                                     ^        */
#ifdef VAL_AC_ALGORITHM_REFUSED
      *iv_return = VAL_AC_ALGORITHM_REFUSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "VAL_AC_UNKNOWN_ALGORITHM", 24)) {
    /*                                     ^        */
#ifdef VAL_AC_UNKNOWN_ALGORITHM
      *iv_return = VAL_AC_UNKNOWN_ALGORITHM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_RESOURCE_UNAVAILABLE", 24)) {
    /*                                     ^        */
#ifdef VAL_RESOURCE_UNAVAILABLE
      *iv_return = VAL_RESOURCE_UNAVAILABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_AC_WRONG_LABEL_COUNT", 24)) {
    /*                                     ^        */
#ifdef VAL_AC_WRONG_LABEL_COUNT
      *iv_return = VAL_AC_WRONG_LABEL_COUNT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_AC_IGNORE_VALIDATION", 24)) {
    /*                                     ^        */
#ifdef VAL_AC_IGNORE_VALIDATION
      *iv_return = VAL_AC_IGNORE_VALIDATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_PROVABLY_UNSECURE", 24)) {
    /*                                     ^        */
#ifdef VAL_AC_PROVABLY_UNSECURE
      *iv_return = VAL_AC_PROVABLY_UNSECURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SR_MKQUERY_INTERNAL_ERROR SR_NAME_EXPANSION_FAILURE
     VAL_AC_KEY_NOT_AUTHORIZED VAL_AC_RRSIG_NOTYETACTIVE */
  /* Offset 21 gives the best switch position.  */
  switch (name[21]) {
  case 'I':
    if (memEQ(name, "VAL_AC_KEY_NOT_AUTHORIZED", 25)) {
    /*                                    ^          */
#ifdef VAL_AC_KEY_NOT_AUTHORIZED
      *iv_return = VAL_AC_KEY_NOT_AUTHORIZED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SR_NAME_EXPANSION_FAILURE", 25)) {
    /*                                    ^          */
#ifdef SR_NAME_EXPANSION_FAILURE
      *iv_return = SR_NAME_EXPANSION_FAILURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SR_MKQUERY_INTERNAL_ERROR", 25)) {
    /*                                    ^          */
#ifdef SR_MKQUERY_INTERNAL_ERROR
      *iv_return = SR_MKQUERY_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_AC_RRSIG_NOTYETACTIVE", 25)) {
    /*                                    ^          */
#ifdef VAL_AC_RRSIG_NOTYETACTIVE
      *iv_return = VAL_AC_RRSIG_NOTYETACTIVE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_30 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     VAL_AC_ALGORITHM_NOT_SUPPORTED VAL_AC_UNKNOWN_DNSKEY_PROTOCOL
     VAL_MASKED_FLAG_CHAIN_COMPLETE */
  /* Offset 23 gives the best switch position.  */
  switch (name[23]) {
  case 'O':
    if (memEQ(name, "VAL_MASKED_FLAG_CHAIN_COMPLETE", 30)) {
    /*                                      ^             */
#ifdef VAL_MASKED_FLAG_CHAIN_COMPLETE
      *iv_return = VAL_MASKED_FLAG_CHAIN_COMPLETE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_AC_ALGORITHM_NOT_SUPPORTED", 30)) {
    /*                                      ^             */
#ifdef VAL_AC_ALGORITHM_NOT_SUPPORTED
      *iv_return = VAL_AC_ALGORITHM_NOT_SUPPORTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_UNKNOWN_DNSKEY_PROTOCOL", 30)) {
    /*                                      ^             */
#ifdef VAL_AC_UNKNOWN_DNSKEY_PROTOCOL
      *iv_return = VAL_AC_UNKNOWN_DNSKEY_PROTOCOL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant (pTHX_ const char *name, STRLEN len, IV *iv_return) {
  /* Initially switch on the length of the name.  */
  /* When generated this function returned values for the list of names given
     in this section of perl code.  Rather than manually editing these functions
     to add or remove constants, which would result in this comment and section
     of code becoming inaccurate, we recommend that you edit this section of
     code, and use it to regenerate a new set of constant functions which you
     then use to replace the originals.

     Regenerate these constant functions by feeding this entire source file to
     perl -x

#!/usr/bin/perl -w
use ExtUtils::Constant qw (constant_types C_constant XS_constant);

my $types = {map {($_, 1)} qw(IV)};
my @names = (qw(ALG_DH ALG_DSASHA1 ALG_DS_HASH_SHA1 ALG_NSEC3_DSASHA1
	       ALG_NSEC3_HASH_SHA1 ALG_NSEC3_RSASHA1 ALG_NSEC_HASH_SHA1
	       ALG_RSAMD5 ALG_RSASHA1 CANNOT_BE_USED CAN_SIGN_KEY CAN_SIGN_ZONE
	       CAN_SIGN_ZONE_AND_KEY DNAME_MAX DNS_PORT EDNS_UDP_SIZE ENVELOPE
	       MAXDNAME MAX_ALIAS_CHAIN_LENGTH MAX_PROOFS NS_CMPRSFLGS
	       NS_INT16SZ NS_INT32SZ NS_MAXCDNAME NS_MAXDNAME NS_PUT16 NS_PUT32
	       Q_ANSWERED Q_ERROR_BASE Q_INIT Q_SENT Q_WAIT_FOR_GLUE RES_RETRY
	       RES_USE_DNSSEC RRSIGLABEL SHA_DIGEST_LENGTH SIGNBY
	       SIG_ACCEPT_WINDOW SR_ANS_BARE_RRSIG SR_ANS_CNAME SR_ANS_DNAME
	       SR_ANS_NACK_NSEC SR_ANS_NACK_NSEC3 SR_ANS_NACK_SOA
	       SR_ANS_STRAIGHT SR_ANS_UNSET SR_CALL_ERROR
	       SR_CONFLICTING_ANSWERS SR_CRED_AUTH_ADD SR_CRED_AUTH_ANS
	       SR_CRED_AUTH_AUTH SR_CRED_FILE SR_CRED_NONAUTH_ADD
	       SR_CRED_NONAUTH_ANS SR_CRED_NONAUTH_AUTH SR_CRED_UNSET
	       SR_DNS_GENERIC_ERROR SR_EDNS_VERSION_ERROR SR_FORMERR
	       SR_HEADER_BADSIZE SR_INTERNAL_ERROR SR_LAST_ERROR
	       SR_MEMORY_ERROR SR_MISSING_GLUE SR_MKQUERY_INTERNAL_ERROR
	       SR_NAME_EXPANSION_FAILURE SR_NOTIMPL SR_NO_ANSWER
	       SR_NO_ANSWER_YET SR_NXDOMAIN SR_RCV_INTERNAL_ERROR
	       SR_REFERRAL_ERROR SR_REFUSED SR_SEND_INTERNAL_ERROR SR_SERVFAIL
	       SR_TSIG_ERROR SR_TSIG_INTERNAL_ERROR SR_UNSET
	       SR_UNSUPP_EDNS0_LABEL SR_WRONG_ANSWER SR_ZI_STATUS_LEARNED
	       SR_ZI_STATUS_PERMANENT SR_ZI_STATUS_UNSET TTL VALIDATOR_LOG_PORT
	       VAL_AC_ALGORITHM_NOT_SUPPORTED VAL_AC_ALGORITHM_REFUSED
	       VAL_AC_BAD_BASE VAL_AC_BAD_DELEGATION VAL_AC_BARE_RRSIG
	       VAL_AC_CAN_VERIFY VAL_AC_DATA_MISSING VAL_AC_DNSKEY_MISSING
	       VAL_AC_DNSKEY_NOMATCH VAL_AC_DNS_ERROR_BASE
	       VAL_AC_DNS_ERROR_LAST VAL_AC_DONT_GO_FURTHER VAL_AC_DS_MISSING
	       VAL_AC_ERROR_BASE VAL_AC_FAIL_BASE VAL_AC_IGNORE_VALIDATION
	       VAL_AC_INIT VAL_AC_INVALID_KEY VAL_AC_INVALID_RRSIG
	       VAL_AC_KEY_NOT_AUTHORIZED VAL_AC_KEY_TOO_LARGE
	       VAL_AC_KEY_TOO_SMALL VAL_AC_LAST_BAD VAL_AC_LAST_ERROR
	       VAL_AC_LAST_FAILURE VAL_AC_LAST_STATE VAL_AC_LOCAL_ANSWER
	       VAL_AC_NEGATIVE_PROOF VAL_AC_NOT_VERIFIED VAL_AC_NO_TRUST_ANCHOR
	       VAL_AC_PROVABLY_UNSECURE VAL_AC_RRSIG_ALGORITHM_MISMATCH
	       VAL_AC_RRSIG_EXPIRED VAL_AC_RRSIG_MISSING
	       VAL_AC_RRSIG_NOTYETACTIVE VAL_AC_RRSIG_VERIFIED
	       VAL_AC_RRSIG_VERIFY_FAILED VAL_AC_SIGNING_KEY
	       VAL_AC_TRUSTED_ZONE VAL_AC_TRUST_KEY VAL_AC_UNKNOWN_ALGORITHM
	       VAL_AC_UNKNOWN_ALGORITHM_LINK VAL_AC_UNKNOWN_DNSKEY_PROTOCOL
	       VAL_AC_UNSET VAL_AC_UNTRUSTED_ZONE VAL_AC_VERIFIED
	       VAL_AC_VERIFIED_LINK VAL_AC_WAIT_FOR_RRSIG VAL_AC_WAIT_FOR_TRUST
	       VAL_AC_WCARD_VERIFIED VAL_AC_WRONG_LABEL_COUNT VAL_BAD_ARGUMENT
	       VAL_BARE_RRSIG VAL_BOGUS VAL_BOGUS_PROOF VAL_BOGUS_PROVABLE
	       VAL_BOGUS_UNPROVABLE VAL_CONF_NOT_FOUND VAL_CONF_PARSE_ERROR
	       VAL_CTX_IDLEN VAL_DNS_ERROR_BASE VAL_DNS_ERROR_LAST
	       VAL_DONT_GO_FURTHER VAL_DONT_KNOW VAL_ERROR VAL_FLAGS_DEFAULT
	       VAL_FLAGS_DONT_VALIDATE VAL_FLAG_CHAIN_COMPLETE
	       VAL_FROM_ADDITIONAL VAL_FROM_ANSWER VAL_FROM_AUTHORITY
	       VAL_FROM_QUERY VAL_FROM_UNSET VAL_IGNORE_VALIDATION
	       VAL_INCOMPLETE_PROOF VAL_INDETERMINATE VAL_INDETERMINATE_DS
	       VAL_INDETERMINATE_PROOF VAL_INTERNAL_ERROR VAL_IRRELEVANT_PROOF
	       VAL_LOCAL_ANSWER VAL_LOG_OPTIONS VAL_MASKED_FLAG_CHAIN_COMPLETE
	       VAL_NONEXISTENT_NAME VAL_NONEXISTENT_NAME_NOCHAIN
	       VAL_NONEXISTENT_NAME_OPTOUT VAL_NONEXISTENT_TYPE
	       VAL_NONEXISTENT_TYPE_NOCHAIN VAL_NOTRUST VAL_NOT_IMPLEMENTED
	       VAL_NO_ERROR VAL_NO_PERMISSION VAL_NO_POLICY VAL_OUT_OF_MEMORY
	       VAL_PROVABLY_UNSECURE VAL_QUERY_MERGE_RRSETS
	       VAL_RESOURCE_UNAVAILABLE VAL_SUCCESS VAL_TRUSTED_ZONE
	       VAL_UNTRUSTED_ZONE VAL_VERIFIED_CHAIN ZONE_USE_NOTHING
	       ZONE_USE_TSIG free_val_addrinfo ns_t_dnskey ns_t_ds ns_t_nsec
	       ns_t_nsec3 ns_t_rrsig p_as_error p_query_error p_val_error
	       policy_entry_t));

print constant_types(); # macro defs
foreach (C_constant ("Net::DNS::SEC::Validator", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "#### XS Section:\n";
print XS_constant ("Net::DNS::SEC::Validator", $types);
__END__
   */

  switch (len) {
  case 3:
    if (memEQ(name, "TTL", 3)) {
#ifdef TTL
      *iv_return = TTL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 6:
    return constant_6 (aTHX_ name, iv_return);
    break;
  case 7:
    if (memEQ(name, "ns_t_ds", 7)) {
#ifdef ns_t_ds
      *iv_return = ns_t_ds;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 8:
    return constant_8 (aTHX_ name, iv_return);
    break;
  case 9:
    return constant_9 (aTHX_ name, iv_return);
    break;
  case 10:
    return constant_10 (aTHX_ name, iv_return);
    break;
  case 11:
    return constant_11 (aTHX_ name, iv_return);
    break;
  case 12:
    return constant_12 (aTHX_ name, iv_return);
    break;
  case 13:
    return constant_13 (aTHX_ name, iv_return);
    break;
  case 14:
    return constant_14 (aTHX_ name, iv_return);
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 16:
    return constant_16 (aTHX_ name, iv_return);
    break;
  case 17:
    return constant_17 (aTHX_ name, iv_return);
    break;
  case 18:
    return constant_18 (aTHX_ name, iv_return);
    break;
  case 19:
    return constant_19 (aTHX_ name, iv_return);
    break;
  case 20:
    return constant_20 (aTHX_ name, iv_return);
    break;
  case 21:
    return constant_21 (aTHX_ name, iv_return);
    break;
  case 22:
    return constant_22 (aTHX_ name, iv_return);
    break;
  case 23:
    return constant_23 (aTHX_ name, iv_return);
    break;
  case 24:
    return constant_24 (aTHX_ name, iv_return);
    break;
  case 25:
    return constant_25 (aTHX_ name, iv_return);
    break;
  case 26:
    if (memEQ(name, "VAL_AC_RRSIG_VERIFY_FAILED", 26)) {
#ifdef VAL_AC_RRSIG_VERIFY_FAILED
      *iv_return = VAL_AC_RRSIG_VERIFY_FAILED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 27:
    if (memEQ(name, "VAL_NONEXISTENT_NAME_OPTOUT", 27)) {
#ifdef VAL_NONEXISTENT_NAME_OPTOUT
      *iv_return = VAL_NONEXISTENT_NAME_OPTOUT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 28:
    /* Names all of length 28.  */
    /* VAL_NONEXISTENT_NAME_NOCHAIN VAL_NONEXISTENT_TYPE_NOCHAIN */
    /* Offset 18 gives the best switch position.  */
    switch (name[18]) {
    case 'M':
      if (memEQ(name, "VAL_NONEXISTENT_NAME_NOCHAIN", 28)) {
      /*                                 ^                */
#ifdef VAL_NONEXISTENT_NAME_NOCHAIN
        *iv_return = VAL_NONEXISTENT_NAME_NOCHAIN;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'P':
      if (memEQ(name, "VAL_NONEXISTENT_TYPE_NOCHAIN", 28)) {
      /*                                 ^                */
#ifdef VAL_NONEXISTENT_TYPE_NOCHAIN
        *iv_return = VAL_NONEXISTENT_TYPE_NOCHAIN;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 29:
    if (memEQ(name, "VAL_AC_UNKNOWN_ALGORITHM_LINK", 29)) {
#ifdef VAL_AC_UNKNOWN_ALGORITHM_LINK
      *iv_return = VAL_AC_UNKNOWN_ALGORITHM_LINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 30:
    return constant_30 (aTHX_ name, iv_return);
    break;
  case 31:
    if (memEQ(name, "VAL_AC_RRSIG_ALGORITHM_MISMATCH", 31)) {
#ifdef VAL_AC_RRSIG_ALGORITHM_MISMATCH
      *iv_return = VAL_AC_RRSIG_ALGORITHM_MISMATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

