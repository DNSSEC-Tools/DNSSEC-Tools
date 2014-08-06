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
constant_8 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     LOG_CRIT LOG_INFO SR_UNSET */
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
  case 'F':
    if (memEQ(name, "LOG_INFO", 8)) {
    /*                     ^       */
#ifdef LOG_INFO
      *iv_return = LOG_INFO;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "LOG_CRIT", 8)) {
    /*                     ^       */
#ifdef LOG_CRIT
      *iv_return = LOG_CRIT;
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
     LOG_ALERT LOG_DEBUG LOG_EMERG VAL_BOGUS */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'A':
    if (memEQ(name, "LOG_ALERT", 9)) {
    /*                   ^          */
#ifdef LOG_ALERT
      *iv_return = LOG_ALERT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'B':
    if (memEQ(name, "VAL_BOGUS", 9)) {
    /*                   ^          */
#ifdef VAL_BOGUS
      *iv_return = VAL_BOGUS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "LOG_DEBUG", 9)) {
    /*                   ^          */
#ifdef LOG_DEBUG
      *iv_return = LOG_DEBUG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "LOG_EMERG", 9)) {
    /*                   ^          */
#ifdef LOG_EMERG
      *iv_return = LOG_EMERG;
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
     LOG_NOTICE MAX_PROOFS SR_FORMERR SR_NOTIMPL SR_REFUSED VAL_EINVAL
     VAL_ENOENT VAL_ENOMEM VAL_ENOSYS */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'A':
    if (memEQ(name, "VAL_EINVAL", 10)) {
    /*                       ^        */
#ifdef VAL_EINVAL
      *iv_return = VAL_EINVAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "LOG_NOTICE", 10)) {
    /*                       ^        */
#ifdef LOG_NOTICE
      *iv_return = LOG_NOTICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_REFUSED", 10)) {
    /*                       ^        */
#ifdef SR_REFUSED
      *iv_return = SR_REFUSED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_ENOMEM", 10)) {
    /*                       ^        */
#ifdef VAL_ENOMEM
      *iv_return = VAL_ENOMEM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "MAX_PROOFS", 10)) {
    /*                       ^        */
#ifdef MAX_PROOFS
      *iv_return = MAX_PROOFS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_ENOENT", 10)) {
    /*                       ^        */
#ifdef VAL_ENOENT
      *iv_return = VAL_ENOENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "SR_NOTIMPL", 10)) {
    /*                       ^        */
#ifdef SR_NOTIMPL
      *iv_return = SR_NOTIMPL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SR_FORMERR", 10)) {
    /*                       ^        */
#ifdef SR_FORMERR
      *iv_return = SR_FORMERR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "VAL_ENOSYS", 10)) {
    /*                       ^        */
#ifdef VAL_ENOSYS
      *iv_return = VAL_ENOSYS;
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
     LOG_WARNING SR_NXDOMAIN SR_SERVFAIL VAL_AC_INIT VAL_AS_DONE VAL_EACCESS
     VAL_NOTRUST VAL_SUCCESS */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'A':
    if (memEQ(name, "LOG_WARNING", 11)) {
    /*                    ^            */
#ifdef LOG_WARNING
      *iv_return = LOG_WARNING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_EACCESS", 11)) {
    /*                    ^            */
#ifdef VAL_EACCESS
      *iv_return = VAL_EACCESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
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
    if (memEQ(name, "VAL_AS_DONE", 11)) {
    /*                    ^            */
#ifdef VAL_AS_DONE
      *iv_return = VAL_AS_DONE;
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
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_12 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     NS_MAXCDNAME SR_NO_ANSWER VAL_AC_TRUST VAL_AC_UNSET VAL_NO_ERROR */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'D':
    if (memEQ(name, "NS_MAXCDNAME", 12)) {
    /*                      ^           */
#ifdef NS_MAXCDNAME
      *iv_return = NS_MAXCDNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_NO_ERROR", 12)) {
    /*                      ^           */
#ifdef VAL_NO_ERROR
      *iv_return = VAL_NO_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SR_NO_ANSWER", 12)) {
    /*                      ^           */
#ifdef SR_NO_ANSWER
      *iv_return = SR_NO_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_AC_TRUST", 12)) {
    /*                      ^           */
#ifdef VAL_AC_TRUST
      *iv_return = VAL_AC_TRUST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_AC_UNSET", 12)) {
    /*                      ^           */
#ifdef VAL_AC_UNSET
      *iv_return = VAL_AC_UNSET;
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
     SR_CALL_ERROR SR_TSIG_ERROR VAL_DNS_ERROR VAL_DONT_KNOW VAL_NO_POLICY
     VAL_PINSECURE ZONE_USE_TSIG */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'A':
    if (memEQ(name, "SR_CALL_ERROR", 13)) {
    /*                   ^               */
#ifdef SR_CALL_ERROR
      *iv_return = SR_CALL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_DNS_ERROR", 13)) {
    /*                   ^               */
#ifdef VAL_DNS_ERROR
      *iv_return = VAL_DNS_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_DONT_KNOW", 13)) {
    /*                   ^               */
#ifdef VAL_DONT_KNOW
      *iv_return = VAL_DONT_KNOW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_NO_POLICY", 13)) {
    /*                   ^               */
#ifdef VAL_NO_POLICY
      *iv_return = VAL_NO_POLICY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_PINSECURE", 13)) {
    /*                   ^               */
#ifdef VAL_PINSECURE
      *iv_return = VAL_PINSECURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_TSIG_ERROR", 13)) {
    /*                   ^               */
#ifdef SR_TSIG_ERROR
      *iv_return = SR_TSIG_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "ZONE_USE_TSIG", 13)) {
    /*                   ^               */
#ifdef ZONE_USE_TSIG
      *iv_return = ZONE_USE_TSIG;
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
     VAL_AC_NO_LINK VAL_BARE_RRSIG VAL_FROM_QUERY VAL_FROM_UNSET VAL_OOB_ANSWER
     VAL_QFLAGS_ANY */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'N':
    if (memEQ(name, "VAL_OOB_ANSWER", 14)) {
    /*                        ^           */
#ifdef VAL_OOB_ANSWER
      *iv_return = VAL_OOB_ANSWER;
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
  case 'S':
    if (memEQ(name, "VAL_QFLAGS_ANY", 14)) {
    /*                        ^           */
#ifdef VAL_QFLAGS_ANY
      *iv_return = VAL_QFLAGS_ANY;
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
    if (memEQ(name, "VAL_AC_NO_LINK", 14)) {
    /*                        ^           */
#ifdef VAL_AC_NO_LINK
      *iv_return = VAL_AC_NO_LINK;
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
     SR_HEADER_ERROR SR_MEMORY_ERROR VAL_AC_BAD_BASE VAL_AC_LAST_BAD
     VAL_AC_VERIFIED VAL_BOGUS_PROOF VAL_FROM_ANSWER VAL_QUERY_ASYNC 
     VAL_AS_INFLIGHT */
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
  case 'E':
    if (memEQ(name, "SR_HEADER_ERROR", 15)) {
    /*                      ^              */
#ifdef SR_HEADER_ERROR
      *iv_return = SR_HEADER_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "VAL_AS_INFLIGHT", 15)) {
    /*                      ^              */
#ifdef VAL_AS_INFLIGHT
      *iv_return = VAL_AS_INFLIGHT;
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
    if (memEQ(name, "VAL_QUERY_ASYNC", 15)) {
    /*                      ^              */
#ifdef VAL_QUERY_ASYNC
      *iv_return = VAL_QUERY_ASYNC;
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
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_16 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SR_NO_ANSWER_YET VAL_AC_DNS_ERROR VAL_AC_FAIL_BASE VAL_AC_PINSECURE
     VAL_BAD_ARGUMENT VAL_QUERY_NO_DLV ZONE_USE_NOTHING */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'A':
    if (memEQ(name, "VAL_AC_FAIL_BASE", 16)) {
    /*                            ^         */
#ifdef VAL_AC_FAIL_BASE
      *iv_return = VAL_AC_FAIL_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_QUERY_NO_DLV", 16)) {
    /*                            ^         */
#ifdef VAL_QUERY_NO_DLV
      *iv_return = VAL_QUERY_NO_DLV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_BAD_ARGUMENT", 16)) {
    /*                            ^         */
#ifdef VAL_BAD_ARGUMENT
      *iv_return = VAL_BAD_ARGUMENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "ZONE_USE_NOTHING", 16)) {
    /*                            ^         */
#ifdef ZONE_USE_NOTHING
      *iv_return = ZONE_USE_NOTHING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_DNS_ERROR", 16)) {
    /*                            ^         */
#ifdef VAL_AC_DNS_ERROR
      *iv_return = VAL_AC_DNS_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_AC_PINSECURE", 16)) {
    /*                            ^         */
#ifdef VAL_AC_PINSECURE
      *iv_return = VAL_AC_PINSECURE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "SR_NO_ANSWER_YET", 16)) {
    /*                            ^         */
#ifdef SR_NO_ANSWER_YET
      *iv_return = SR_NO_ANSWER_YET;
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
     SR_INTERNAL_ERROR VAL_AC_BARE_RRSIG VAL_AC_CAN_VERIFY VAL_AC_DS_MISSING
     VAL_AC_DS_NOMATCH VAL_AC_ERROR_BASE VAL_AC_INVALID_DS VAL_AC_LAST_ERROR
     VAL_AC_LAST_STATE VAL_AS_NO_ANSWERS VAL_NO_PERMISSION VAL_OUT_OF_MEMORY
     VAL_QUERY_RECURSE VAL_QUERY_ITERATE */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'B':
    if (memEQ(name, "VAL_AC_BARE_RRSIG", 17)) {
    /*                      ^                */
#ifdef VAL_AC_BARE_RRSIG
      *iv_return = VAL_AC_BARE_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "VAL_AC_CAN_VERIFY", 17)) {
    /*                      ^                */
#ifdef VAL_AC_CAN_VERIFY
      *iv_return = VAL_AC_CAN_VERIFY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_AC_DS_MISSING", 17)) {
    /*                      ^                */
#ifdef VAL_AC_DS_MISSING
      *iv_return = VAL_AC_DS_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_DS_NOMATCH", 17)) {
    /*                      ^                */
#ifdef VAL_AC_DS_NOMATCH
      *iv_return = VAL_AC_DS_NOMATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_AC_ERROR_BASE", 17)) {
    /*                      ^                */
#ifdef VAL_AC_ERROR_BASE
      *iv_return = VAL_AC_ERROR_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "VAL_AC_INVALID_DS", 17)) {
    /*                      ^                */
#ifdef VAL_AC_INVALID_DS
      *iv_return = VAL_AC_INVALID_DS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_AC_LAST_ERROR", 17)) {
    /*                      ^                */
#ifdef VAL_AC_LAST_ERROR
      *iv_return = VAL_AC_LAST_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_LAST_STATE", 17)) {
    /*                      ^                */
#ifdef VAL_AC_LAST_STATE
      *iv_return = VAL_AC_LAST_STATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_AS_NO_ANSWERS", 17)) {
    /*                      ^                */
#ifdef VAL_AS_NO_ANSWERS
      *iv_return = VAL_AS_NO_ANSWERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_NO_PERMISSION", 17)) {
    /*                      ^                */
#ifdef VAL_NO_PERMISSION
      *iv_return = VAL_NO_PERMISSION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SR_INTERNAL_ERROR", 17)) {
    /*                      ^                */
#ifdef SR_INTERNAL_ERROR
      *iv_return = SR_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_QUERY_RECURSE", 17)) {
    /*                      ^                */
#ifdef VAL_QUERY_RECURSE
      *iv_return = VAL_QUERY_RECURSE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_QUERY_ITERATE", 17)) {
    /*                      ^                */
#ifdef VAL_QUERY_ITERATE
      *iv_return = VAL_QUERY_ITERATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_OUT_OF_MEMORY", 17)) {
    /*                      ^                */
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
     LIBSRES_NS_STAGGER SR_ZI_STATUS_UNSET VAL_AC_INVALID_KEY
     VAL_AC_SIGNING_KEY VAL_AC_TRUST_NOCHK VAL_AC_TRUST_POINT
     VAL_BARE_TRUST_KEY VAL_BOGUS_PROVABLE VAL_CONF_NOT_FOUND
     VAL_FROM_AUTHORITY VAL_INTERNAL_ERROR 
     VAL_TRUSTED_ANSWER VAL_UNTRUSTED_ZONE */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'A':
    if (memEQ(name, "LIBSRES_NS_STAGGER", 18)) {
    /*                            ^           */
#ifdef LIBSRES_NS_STAGGER
      *iv_return = LIBSRES_NS_STAGGER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_AC_INVALID_KEY", 18)) {
    /*                            ^           */
#ifdef VAL_AC_INVALID_KEY
      *iv_return = VAL_AC_INVALID_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_INTERNAL_ERROR", 18)) {
    /*                            ^           */
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
    /*                            ^           */
#ifdef VAL_CONF_NOT_FOUND
      *iv_return = VAL_CONF_NOT_FOUND;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "VAL_AC_SIGNING_KEY", 18)) {
    /*                            ^           */
#ifdef VAL_AC_SIGNING_KEY
      *iv_return = VAL_AC_SIGNING_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_AC_TRUST_NOCHK", 18)) {
    /*                            ^           */
#ifdef VAL_AC_TRUST_NOCHK
      *iv_return = VAL_AC_TRUST_NOCHK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_TRUSTED_ANSWER", 18)) {
    /*                            ^           */
#ifdef VAL_TRUSTED_ANSWER
      *iv_return = VAL_TRUSTED_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_FROM_AUTHORITY", 18)) {
    /*                            ^           */
#ifdef VAL_FROM_AUTHORITY
      *iv_return = VAL_FROM_AUTHORITY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_AC_TRUST_POINT", 18)) {
    /*                            ^           */
#ifdef VAL_AC_TRUST_POINT
      *iv_return = VAL_AC_TRUST_POINT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_BARE_TRUST_KEY", 18)) {
    /*                            ^           */
#ifdef VAL_BARE_TRUST_KEY
      *iv_return = VAL_BARE_TRUST_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SR_ZI_STATUS_UNSET", 18)) {
    /*                            ^           */
#ifdef SR_ZI_STATUS_UNSET
      *iv_return = SR_ZI_STATUS_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    } else if (memEQ(name, "VAL_POL_GOPT_UNSET", 18)) {
    /*                                   ^           */
#ifdef VAL_POL_GOPT_UNSET
      *iv_return = VAL_POL_GOPT_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "VAL_BOGUS_PROVABLE", 18)) {
    /*                            ^           */
#ifdef VAL_BOGUS_PROVABLE
      *iv_return = VAL_BOGUS_PROVABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_UNTRUSTED_ZONE", 18)) {
    /*                            ^           */
#ifdef VAL_UNTRUSTED_ZONE
      *iv_return = VAL_UNTRUSTED_ZONE;
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
     VAL_AC_DATA_MISSING VAL_AC_LAST_FAILURE VAL_AC_NOT_VERIFIED
     VAL_AC_TRUST_ANCHOR VAL_AS_CB_COMPLETED VAL_AS_IGNORE_CACHE
     VAL_AS_NO_CALLBACKS VAL_FROM_ADDITIONAL VAL_NOT_IMPLEMENTED
     VAL_POL_GOPT_ENABLE VAL_QFLAGS_USERMASK VAL_QUERY_AC_DETAIL
     VAL_QUERY_USING_DLV */
  /* Offset 11 gives the best switch position.  */
  switch (name[11]) {
  case 'A':
    if (memEQ(name, "VAL_AS_NO_CALLBACKS", 19)) {
    /*                          ^              */
#ifdef VAL_AS_NO_CALLBACKS
      *iv_return = VAL_AS_NO_CALLBACKS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'C':
    if (memEQ(name, "VAL_QUERY_AC_DETAIL", 19)) {
    /*                          ^              */
#ifdef VAL_QUERY_AC_DETAIL
      *iv_return = VAL_QUERY_AC_DETAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_FROM_ADDITIONAL", 19)) {
    /*                          ^              */
#ifdef VAL_FROM_ADDITIONAL
      *iv_return = VAL_FROM_ADDITIONAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_NOT_IMPLEMENTED", 19)) {
    /*                          ^              */
#ifdef VAL_NOT_IMPLEMENTED
      *iv_return = VAL_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "CTX_DYN_POL_RES_NRD", 19)) {
    /*                          ^              */
#ifdef VAL_NOT_IMPLEMENTED
      *iv_return = VAL_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "CTX_DYN_POL_VAL_OVR", 19)) {
    /*                          ^              */
#ifdef VAL_NOT_IMPLEMENTED
      *iv_return = VAL_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "CTX_DYN_POL_RES_OVR", 19)) {
    /*                          ^              */
#ifdef VAL_NOT_IMPLEMENTED
      *iv_return = VAL_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "CTX_DYN_POL_GLO_OVR", 19)) {
    /*                          ^              */
#ifdef VAL_NOT_IMPLEMENTED
      *iv_return = VAL_NOT_IMPLEMENTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_AS_CB_COMPLETED", 19)) {
    /*                          ^              */
#ifdef VAL_AS_CB_COMPLETED
      *iv_return = VAL_AS_CB_COMPLETED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AS_IGNORE_CACHE", 19)) {
    /*                          ^              */
#ifdef VAL_AS_IGNORE_CACHE
      *iv_return = VAL_AS_IGNORE_CACHE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_QUERY_USING_DLV", 19)) {
    /*                          ^              */
#ifdef VAL_QUERY_USING_DLV
      *iv_return = VAL_QUERY_USING_DLV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_AC_TRUST_ANCHOR", 19)) {
    /*                          ^              */
#ifdef VAL_AC_TRUST_ANCHOR
      *iv_return = VAL_AC_TRUST_ANCHOR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_POL_GOPT_ENABLE", 19)) {
    /*                          ^              */
#ifdef VAL_POL_GOPT_ENABLE
      *iv_return = VAL_POL_GOPT_ENABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_QFLAGS_USERMASK", 19)) {
    /*                          ^              */
#ifdef VAL_QFLAGS_USERMASK
      *iv_return = VAL_QFLAGS_USERMASK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "VAL_AC_NOT_VERIFIED", 19)) {
    /*                          ^              */
#ifdef VAL_AC_NOT_VERIFIED
      *iv_return = VAL_AC_NOT_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_AC_DATA_MISSING", 19)) {
    /*                          ^              */
#ifdef VAL_AC_DATA_MISSING
      *iv_return = VAL_AC_DATA_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_LAST_FAILURE", 19)) {
    /*                          ^              */
#ifdef VAL_AC_LAST_FAILURE
      *iv_return = VAL_AC_LAST_FAILURE;
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
     SR_DNS_GENERIC_ERROR SR_ZI_STATUS_LEARNED VAL_AC_INVALID_RRSIG
     VAL_AC_RRSIG_EXPIRED VAL_AC_RRSIG_MISSING VAL_AC_VERIFIED_LINK
     VAL_CONF_PARSE_ERROR VAL_INCOMPLETE_PROOF VAL_IRRELEVANT_PROOF
     VAL_NONEXISTENT_NAME VAL_NONEXISTENT_TYPE VAL_POL_GOPT_DISABLE
     VAL_UNTRUSTED_ANSWER VAL_VALIDATED_ANSWER VAL_QUERY_SKIP_CACHE */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'A':
    if (memEQ(name, "SR_ZI_STATUS_LEARNED", 20)) {
    /*                       ^                  */
#ifdef SR_ZI_STATUS_LEARNED
      *iv_return = SR_ZI_STATUS_LEARNED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "VAL_VALIDATED_ANSWER", 20)) {
    /*                       ^                  */
#ifdef VAL_VALIDATED_ANSWER
      *iv_return = VAL_VALIDATED_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_DNS_GENERIC_ERROR", 20)) {
    /*                       ^                  */
#ifdef SR_DNS_GENERIC_ERROR
      *iv_return = SR_DNS_GENERIC_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_VERIFIED_LINK", 20)) {
    /*                       ^                  */
#ifdef VAL_AC_VERIFIED_LINK
      *iv_return = VAL_AC_VERIFIED_LINK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "VAL_POL_GOPT_DISABLE", 20)) {
    /*                       ^                  */
#ifdef VAL_POL_GOPT_DISABLE
      *iv_return = VAL_POL_GOPT_DISABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_IRRELEVANT_PROOF", 20)) {
    /*                       ^                  */
#ifdef VAL_IRRELEVANT_PROOF
      *iv_return = VAL_IRRELEVANT_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "VAL_INCOMPLETE_PROOF", 20)) {
    /*                       ^                  */
#ifdef VAL_INCOMPLETE_PROOF
      *iv_return = VAL_INCOMPLETE_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_AC_INVALID_RRSIG", 20)) {
    /*                       ^                  */
#ifdef VAL_AC_INVALID_RRSIG
      *iv_return = VAL_AC_INVALID_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_RRSIG_EXPIRED", 20)) {
    /*                       ^                  */
#ifdef VAL_AC_RRSIG_EXPIRED
      *iv_return = VAL_AC_RRSIG_EXPIRED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_RRSIG_MISSING", 20)) {
    /*                       ^                  */
#ifdef VAL_AC_RRSIG_MISSING
      *iv_return = VAL_AC_RRSIG_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_UNTRUSTED_ANSWER", 20)) {
    /*                       ^                  */
#ifdef VAL_UNTRUSTED_ANSWER
      *iv_return = VAL_UNTRUSTED_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'X':
    if (memEQ(name, "VAL_NONEXISTENT_NAME", 20)) {
    /*                       ^                  */
#ifdef VAL_NONEXISTENT_NAME
      *iv_return = VAL_NONEXISTENT_NAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_NONEXISTENT_TYPE", 20)) {
    /*                       ^                  */
#ifdef VAL_NONEXISTENT_TYPE
      *iv_return = VAL_NONEXISTENT_TYPE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "VAL_QUERY_SKIP_CACHE", 20)) {
    /*                       ^                  */
#ifdef VAL_QUERY_SKIP_CACHE
      *iv_return = VAL_QUERY_SKIP_CACHE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "VAL_CONF_PARSE_ERROR", 20)) {
    /*                       ^                  */
#ifdef VAL_CONF_PARSE_ERROR
      *iv_return = VAL_CONF_PARSE_ERROR;
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
     SR_EDNS_VERSION_ERROR SR_RCV_INTERNAL_ERROR SR_UNSUPP_EDNS0_LABEL
     VAL_AC_DNSKEY_MISSING VAL_AC_DNSKEY_NOMATCH VAL_AC_NEGATIVE_PROOF
     VAL_AC_RRSIG_VERIFIED VAL_AC_UNTRUSTED_ZONE VAL_AC_WAIT_FOR_RRSIG
     VAL_AC_WAIT_FOR_TRUST VAL_AC_WCARD_VERIFIED VAL_AS_NO_NEW_QUERIES
     VAL_IGNORE_VALIDATION VAL_POL_GOPT_OVERRIDE VAL_QFLAGS_CACHE_MASK 
     VAL_QUERY_IGNORE_SKEW */
  /* Offset 20 gives the best switch position.  */
  switch (name[20]) {
  case 'D':
    if (memEQ(name, "VAL_AC_RRSIG_VERIFIE", 20)) {
    /*                                   D      */
#ifdef VAL_AC_RRSIG_VERIFIED
      *iv_return = VAL_AC_RRSIG_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_WCARD_VERIFIE", 20)) {
    /*                                   D      */
#ifdef VAL_AC_WCARD_VERIFIED
      *iv_return = VAL_AC_WCARD_VERIFIED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_AC_UNTRUSTED_ZON", 20)) {
    /*                                   E      */
#ifdef VAL_AC_UNTRUSTED_ZONE
      *iv_return = VAL_AC_UNTRUSTED_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_POL_GOPT_OVERRID", 20)) {
    /*                                   E      */
#ifdef VAL_POL_GOPT_OVERRIDE
      *iv_return = VAL_POL_GOPT_OVERRIDE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "VAL_AC_NEGATIVE_PROO", 20)) {
    /*                                   F      */
#ifdef VAL_AC_NEGATIVE_PROOF
      *iv_return = VAL_AC_NEGATIVE_PROOF;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "VAL_AC_DNSKEY_MISSIN", 20)) {
    /*                                   G      */
#ifdef VAL_AC_DNSKEY_MISSING
      *iv_return = VAL_AC_DNSKEY_MISSING;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_WAIT_FOR_RRSI", 20)) {
    /*                                   G      */
#ifdef VAL_AC_WAIT_FOR_RRSIG
      *iv_return = VAL_AC_WAIT_FOR_RRSIG;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'H':
    if (memEQ(name, "VAL_AC_DNSKEY_NOMATC", 20)) {
    /*                                   H      */
#ifdef VAL_AC_DNSKEY_NOMATCH
      *iv_return = VAL_AC_DNSKEY_NOMATCH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'K':
    if (memEQ(name, "VAL_QFLAGS_CACHE_MAS", 20)) {
    /*                                   K      */
#ifdef VAL_QFLAGS_CACHE_MASK
      *iv_return = VAL_QFLAGS_CACHE_MASK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "SR_UNSUPP_EDNS0_LABE", 20)) {
    /*                                   L      */
#ifdef SR_UNSUPP_EDNS0_LABEL
      *iv_return = SR_UNSUPP_EDNS0_LABEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_IGNORE_VALIDATIO", 20)) {
    /*                                   N      */
#ifdef VAL_IGNORE_VALIDATION
      *iv_return = VAL_IGNORE_VALIDATION;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "SR_EDNS_VERSION_ERRO", 20)) {
    /*                                   R      */
#ifdef SR_EDNS_VERSION_ERROR
      *iv_return = SR_EDNS_VERSION_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_RCV_INTERNAL_ERRO", 20)) {
    /*                                   R      */
#ifdef SR_RCV_INTERNAL_ERROR
      *iv_return = SR_RCV_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "VAL_AS_NO_NEW_QUERIE", 20)) {
    /*                                   S      */
#ifdef VAL_AS_NO_NEW_QUERIES
      *iv_return = VAL_AS_NO_NEW_QUERIES;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "VAL_AC_WAIT_FOR_TRUS", 20)) {
    /*                                   T      */
#ifdef VAL_AC_WAIT_FOR_TRUST
      *iv_return = VAL_AC_WAIT_FOR_TRUST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'W':
    if (memEQ(name, "VAL_QUERY_IGNORE_SKE", 20)) {
    /*                                   W      */
#ifdef VAL_QUERY_IGNORE_SKEW
      *iv_return = VAL_QUERY_IGNORE_SKEW;
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
     SR_SEND_INTERNAL_ERROR SR_TSIG_INTERNAL_ERROR SR_ZI_STATUS_PERMANENT
     VAL_AC_DONT_GO_FURTHER VAL_QUERY_GLUE_REQUEST */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'A':
    if (memEQ(name, "VAL_AC_DONT_GO_FURTHER", 22)) {
    /*                   ^                        */
#ifdef VAL_AC_DONT_GO_FURTHER
      *iv_return = VAL_AC_DONT_GO_FURTHER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "SR_SEND_INTERNAL_ERROR", 22)) {
    /*                   ^                        */
#ifdef SR_SEND_INTERNAL_ERROR
      *iv_return = SR_SEND_INTERNAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "SR_ZI_STATUS_PERMANENT", 22)) {
    /*                   ^                        */
#ifdef SR_ZI_STATUS_PERMANENT
      *iv_return = SR_ZI_STATUS_PERMANENT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Q':
    if (memEQ(name, "VAL_QUERY_GLUE_REQUEST", 22)) {
    /*                   ^                        */
#ifdef VAL_QUERY_GLUE_REQUEST
      *iv_return = VAL_QUERY_GLUE_REQUEST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_TSIG_INTERNAL_ERROR", 22)) {
    /*                   ^                        */
#ifdef SR_TSIG_INTERNAL_ERROR
      *iv_return = SR_TSIG_INTERNAL_ERROR;
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
     VAL_FLAG_CHAIN_COMPLETE VAL_PINSECURE_UNTRUSTED VAL_QFLAGS_NOCACHE_MASK
     VAL_QUERY_DONT_VALIDATE VAL_QUERY_SKIP_RESOLVER */
  /* Offset 12 gives the best switch position.  */
  switch (name[12]) {
  case 'E':
    if (memEQ(name, "VAL_PINSECURE_UNTRUSTED", 23)) {
    /*                           ^                 */
#ifdef VAL_PINSECURE_UNTRUSTED
      *iv_return = VAL_PINSECURE_UNTRUSTED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "VAL_FLAG_CHAIN_COMPLETE", 23)) {
    /*                           ^                 */
#ifdef VAL_FLAG_CHAIN_COMPLETE
      *iv_return = VAL_FLAG_CHAIN_COMPLETE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    } 
    if (memEQ(name, "VAL_QUERY_SKIP_RESOLVER", 23)) {
    /*                           ^                 */
#ifdef VAL_QUERY_SKIP_RESOLVER
      *iv_return = VAL_QUERY_SKIP_RESOLVER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "VAL_QUERY_DONT_VALIDATE", 23)) {
    /*                           ^                 */
#ifdef VAL_QUERY_DONT_VALIDATE
      *iv_return = VAL_QUERY_DONT_VALIDATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_QFLAGS_NOCACHE_MASK", 23)) {
    /*                           ^                 */
#ifdef VAL_QFLAGS_NOCACHE_MASK
      *iv_return = VAL_QFLAGS_NOCACHE_MASK;
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
     VAL_AC_IGNORE_VALIDATION VAL_AC_WRONG_LABEL_COUNT VAL_AS_CTX_USER_SUPPLIED
     VAL_QUERY_EDNS0_FALLBACK VAL_RESOURCE_UNAVAILABLE
     */
  /* Offset 22 gives the best switch position.  */
  switch (name[22]) {
  case 'C':
    if (memEQ(name, "VAL_QUERY_EDNS0_FALLBACK", 24)) {
    /*                                     ^        */
#ifdef VAL_QUERY_EDNS0_FALLBACK
      *iv_return = VAL_QUERY_EDNS0_FALLBACK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_AS_CTX_USER_SUPPLIED", 24)) {
    /*                                     ^        */
#ifdef VAL_AS_CTX_USER_SUPPLIED
      *iv_return = VAL_AS_CTX_USER_SUPPLIED;
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
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_25 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     SR_MKQUERY_INTERNAL_ERROR SR_NAME_EXPANSION_FAILURE
     VAL_AC_RRSIG_NOTYETACTIVE */
  /* Offset 15 gives the best switch position.  */
  switch (name[15]) {
  case 'O':
    if (memEQ(name, "SR_NAME_EXPANSION_FAILURE", 25)) {
    /*                              ^                */
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
    /*                              ^                */
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
    /*                              ^                */
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
constant_26 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     VAL_AC_RRSIG_VERIFIED_SKEW VAL_AC_RRSIG_VERIFY_FAILED
     VAL_AC_WCARD_VERIFIED_SKEW VAL_QUERY_CHECK_ALL_RRSIGS*/
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'C':
    if (memEQ(name, "VAL_AC_WCARD_VERIFIED_SKEW", 26)) {
    /*                       ^                        */
#ifdef VAL_AC_WCARD_VERIFIED_SKEW
      *iv_return = VAL_AC_WCARD_VERIFIED_SKEW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_AC_RRSIG_VERIFIED_SKEW", 26)) {
    /*                       ^                        */
#ifdef VAL_AC_RRSIG_VERIFIED_SKEW
      *iv_return = VAL_AC_RRSIG_VERIFIED_SKEW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_AC_RRSIG_VERIFY_FAILED", 26)) {
    /*                       ^                        */
#ifdef VAL_AC_RRSIG_VERIFY_FAILED
      *iv_return = VAL_AC_RRSIG_VERIFY_FAILED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "VAL_QUERY_CHECK_ALL_RRSIGS", 26)) {
    /*                       ^                        */
#ifdef VAL_QUERY_CHECK_ALL_RRSIGS
      *iv_return = VAL_QUERY_CHECK_ALL_RRSIGS;
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
my @names = (qw(LIBSRES_NS_STAGGER LOG_ALERT LOG_CRIT LOG_DEBUG LOG_EMERG
	       LOG_ERR LOG_INFO LOG_NOTICE LOG_WARNING MAX_PROOFS NS_MAXCDNAME
	       SOCKET SR_CALL_ERROR SR_DNS_GENERIC_ERROR SR_EDNS_VERSION_ERROR
	       SR_FORMERR SR_HEADER_ERROR SR_INTERNAL_ERROR SR_MEMORY_ERROR
	       SR_MKQUERY_INTERNAL_ERROR SR_NAME_EXPANSION_FAILURE SR_NOTIMPL
	       SR_NO_ANSWER SR_NO_ANSWER_YET SR_NXDOMAIN SR_RCV_INTERNAL_ERROR
	       SR_REFUSED SR_SEND_INTERNAL_ERROR SR_SERVFAIL SR_TSIG_ERROR
	       SR_TSIG_INTERNAL_ERROR SR_UNSET SR_UNSUPP_EDNS0_LABEL
	       SR_ZI_STATUS_LEARNED SR_ZI_STATUS_PERMANENT SR_ZI_STATUS_UNSET
	       VAL_AC_ALGORITHM_NOT_SUPPORTED VAL_AC_BAD_BASE VAL_AC_BARE_RRSIG
	       VAL_AC_CAN_VERIFY VAL_AC_DATA_MISSING VAL_AC_DNSKEY_MISSING
	       VAL_AC_DNSKEY_NOMATCH VAL_AC_DNS_ERROR VAL_AC_DONT_GO_FURTHER
	       VAL_AC_DS_MISSING VAL_AC_DS_NOMATCH VAL_AC_ERROR_BASE
	       VAL_AC_FAIL_BASE VAL_AC_IGNORE_VALIDATION VAL_AC_INIT
	       VAL_AC_INVALID_DS VAL_AC_INVALID_KEY VAL_AC_INVALID_RRSIG
	       VAL_AC_LAST_BAD VAL_AC_LAST_ERROR VAL_AC_LAST_FAILURE
	       VAL_AC_LAST_STATE VAL_AC_NEGATIVE_PROOF VAL_AC_NOT_VERIFIED
	       VAL_AC_NO_LINK VAL_AC_PINSECURE VAL_AC_RRSIG_ALGORITHM_MISMATCH
	       VAL_AC_RRSIG_EXPIRED VAL_AC_RRSIG_MISSING
	       VAL_AC_RRSIG_NOTYETACTIVE VAL_AC_RRSIG_VERIFIED
	       VAL_AC_RRSIG_VERIFIED_SKEW VAL_AC_RRSIG_VERIFY_FAILED
	       VAL_AC_SIGNING_KEY VAL_AC_TRUST VAL_AC_TRUST_ANCHOR
	       VAL_AC_TRUST_NOCHK VAL_AC_TRUST_POINT
	       VAL_AC_UNKNOWN_ALGORITHM_LINK VAL_AC_UNKNOWN_DNSKEY_PROTOCOL
	       VAL_AC_UNSET VAL_AC_UNTRUSTED_ZONE VAL_AC_VERIFIED
	       VAL_AC_VERIFIED_LINK VAL_AC_WAIT_FOR_RRSIG VAL_AC_WAIT_FOR_TRUST
	       VAL_AC_WCARD_VERIFIED VAL_AC_WCARD_VERIFIED_SKEW
	       VAL_AC_WRONG_LABEL_COUNT VAL_AS_CB_COMPLETED
	       VAL_AS_CTX_USER_SUPPLIED VAL_AS_DONE VAL_AS_IGNORE_CACHE
	       VAL_AS_NO_ANSWERS VAL_AS_NO_CALLBACKS VAL_AS_NO_NEW_QUERIES
	       VAL_BAD_ARGUMENT VAL_BARE_RRSIG VAL_BARE_TRUST_KEY VAL_BOGUS
	       VAL_BOGUS_PROOF VAL_BOGUS_PROVABLE VAL_CONF_NOT_FOUND
	       VAL_CONF_PARSE_ERROR VAL_DNS_ERROR VAL_DONT_KNOW VAL_EACCESS
	       VAL_EINVAL VAL_ENOENT VAL_ENOMEM VAL_ENOSYS
	       VAL_FLAG_CHAIN_COMPLETE VAL_FROM_ADDITIONAL VAL_FROM_ANSWER
	       VAL_FROM_AUTHORITY VAL_FROM_QUERY VAL_FROM_UNSET
	       VAL_IGNORE_VALIDATION VAL_INCOMPLETE_PROOF VAL_INTERNAL_ERROR
	       VAL_IRRELEVANT_PROOF VAL_MASKED_FLAG_CHAIN_COMPLETE
	       VAL_NONEXISTENT_NAME VAL_NONEXISTENT_NAME_NOCHAIN
	       VAL_NONEXISTENT_TYPE VAL_NONEXISTENT_TYPE_NOCHAIN VAL_NOTRUST
	       VAL_NOT_IMPLEMENTED VAL_NO_ERROR VAL_NO_PERMISSION VAL_NO_POLICY
	       VAL_OOB_ANSWER VAL_OUT_OF_MEMORY VAL_PINSECURE
	       VAL_PINSECURE_UNTRUSTED VAL_POL_GOPT_DISABLE VAL_POL_GOPT_ENABLE
	       VAL_POL_GOPT_OVERRIDE VAL_QFLAGS_ANY VAL_QFLAGS_CACHE_MASK
	       VAL_QFLAGS_NOCACHE_MASK VAL_QFLAGS_USERMASK VAL_QUERY_AC_DETAIL
	       VAL_QUERY_ASYNC VAL_QUERY_DONT_VALIDATE VAL_QUERY_EDNS0_FALLBACK
	       VAL_QUERY_GLUE_REQUEST VAL_QUERY_NO_DLV VAL_QUERY_CHECK_ALL_RRSIGS
	       VAL_QUERY_NO_EDNS0_FALLBACK VAL_QUERY_RECURSE VAL_QUERY_ITERATE
	       VAL_QUERY_USING_DLV
	       VAL_RESOURCE_UNAVAILABLE VAL_SUCCESS VAL_TRUSTED_ANSWER
	       VAL_UNTRUSTED_ANSWER VAL_UNTRUSTED_ZONE VAL_VALIDATED_ANSWER
	       ZONE_USE_NOTHING ZONE_USE_TSIG));

print constant_types(), "\n"; # macro defs
foreach (C_constant ("Net-DNS-Sec-Validator", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "\n#### XS Section:\n";
print XS_constant ("Net-DNS-Sec-Validator", $types);
__END__
   */

  switch (len) {
  case 7:
    if (memEQ(name, "LOG_ERR", 7)) {
#ifdef LOG_ERR
      *iv_return = LOG_ERR;
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
    return constant_26 (aTHX_ name, iv_return);
    break;
  case 27:
    /* Names all of length 27.  */
    /* VAL_QUERY_NO_EDNS0_FALLBACK VAL_QUERY_MARK_FOR_DELETION */
    /* Offset 10 gives the best switch position.  */
    switch (name[10]) {
    case 'M':
      if (memEQ(name, "VAL_QUERY_MARK_FOR_DELETION", 27)) {
      /*                         ^                  */
#ifdef VAL_QUERY_MARK_FOR_DELETION
        *iv_return = VAL_QUERY_MARK_FOR_DELETION;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'N':
      if (memEQ(name, "VAL_QUERY_NO_EDNS0_FALLBACK", 27)) {
      /*                         ^                  */
#ifdef VAL_QUERY_NO_EDNS0_FALLBACK
        *iv_return = VAL_QUERY_NO_EDNS0_FALLBACK;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
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

