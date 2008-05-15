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
constant_10 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_RSAMD5 Q_ANSWERED RRSIGLABEL */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'L':
    if (memEQ(name, "RRSIGLABEL", 10)) {
    /*                    ^           */
#ifdef RRSIGLABEL
      *iv_return = RRSIGLABEL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "ALG_RSAMD5", 10)) {
    /*                    ^           */
#ifdef ALG_RSAMD5
      *iv_return = ALG_RSAMD5;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'W':
    if (memEQ(name, "Q_ANSWERED", 10)) {
    /*                    ^           */
#ifdef Q_ANSWERED
      *iv_return = Q_ANSWERED;
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
     ALG_DSASHA1 ALG_RSASHA1 SR_ANS_NACK */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'D':
    if (memEQ(name, "ALG_DSASHA1", 11)) {
    /*                   ^             */
#ifdef ALG_DSASHA1
      *iv_return = ALG_DSASHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SR_ANS_NACK", 11)) {
    /*                   ^             */
#ifdef SR_ANS_NACK
      *iv_return = SR_ANS_NACK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "ALG_RSASHA1", 11)) {
    /*                   ^             */
#ifdef ALG_RSASHA1
      *iv_return = ALG_RSASHA1;
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
     CAN_SIGN_KEY Q_ERROR_BASE SR_ANS_CNAME SR_ANS_DNAME SR_ANS_UNSET
     SR_CRED_FILE */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'C':
    if (memEQ(name, "SR_ANS_CNAME", 12)) {
    /*                      ^           */
#ifdef SR_ANS_CNAME
      *iv_return = SR_ANS_CNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SR_ANS_DNAME", 12)) {
    /*                      ^           */
#ifdef SR_ANS_DNAME
      *iv_return = SR_ANS_DNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "CAN_SIGN_KEY", 12)) {
    /*                      ^           */
#ifdef CAN_SIGN_KEY
      *iv_return = CAN_SIGN_KEY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SR_ANS_UNSET", 12)) {
    /*                      ^           */
#ifdef SR_ANS_UNSET
      *iv_return = SR_ANS_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "Q_ERROR_BASE", 12)) {
    /*                      ^           */
#ifdef Q_ERROR_BASE
      *iv_return = Q_ERROR_BASE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_CRED_FILE", 12)) {
    /*                      ^           */
#ifdef SR_CRED_FILE
      *iv_return = SR_CRED_FILE;
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
     CAN_SIGN_ZONE EDNS_UDP_SIZE Q_QUERY_ERROR SR_CRED_UNSET VAL_CTX_IDLEN */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
  case 'I':
    if (memEQ(name, "EDNS_UDP_SIZE", 13)) {
    /*                         ^         */
#ifdef EDNS_UDP_SIZE
      *iv_return = EDNS_UDP_SIZE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_CTX_IDLEN", 13)) {
    /*                         ^         */
#ifdef VAL_CTX_IDLEN
      *iv_return = VAL_CTX_IDLEN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "CAN_SIGN_ZONE", 13)) {
    /*                         ^         */
#ifdef CAN_SIGN_ZONE
      *iv_return = CAN_SIGN_ZONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "Q_QUERY_ERROR", 13)) {
    /*                         ^         */
#ifdef Q_QUERY_ERROR
      *iv_return = Q_QUERY_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_CRED_UNSET", 13)) {
    /*                         ^         */
#ifdef SR_CRED_UNSET
      *iv_return = SR_CRED_UNSET;
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
     CANNOT_BE_USED Q_MISSING_GLUE Q_WRONG_ANSWER VAL_FROM_QUERY VAL_FROM_UNSET
     VAL_QFLAGS_ANY */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'F':
    if (memEQ(name, "VAL_QFLAGS_ANY", 14)) {
    /*                    ^               */
#ifdef VAL_QFLAGS_ANY
      *iv_return = VAL_QFLAGS_ANY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "Q_WRONG_ANSWER", 14)) {
    /*                    ^               */
#ifdef Q_WRONG_ANSWER
      *iv_return = Q_WRONG_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_FROM_QUERY", 14)) {
    /*                    ^               */
#ifdef VAL_FROM_QUERY
      *iv_return = VAL_FROM_QUERY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "VAL_FROM_UNSET", 14)) {
    /*                    ^               */
#ifdef VAL_FROM_UNSET
      *iv_return = VAL_FROM_UNSET;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "Q_MISSING_GLUE", 14)) {
    /*                    ^               */
#ifdef Q_MISSING_GLUE
      *iv_return = Q_MISSING_GLUE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "CANNOT_BE_USED", 14)) {
    /*                    ^               */
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
     Q_WAIT_FOR_GLUE SR_ANS_STRAIGHT VAL_FROM_ANSWER VAL_LOG_OPTIONS */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'O':
    if (memEQ(name, "VAL_LOG_OPTIONS", 15)) {
    /*                    ^                */
#ifdef VAL_LOG_OPTIONS
      *iv_return = VAL_LOG_OPTIONS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_FROM_ANSWER", 15)) {
    /*                    ^                */
#ifdef VAL_FROM_ANSWER
      *iv_return = VAL_FROM_ANSWER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "SR_ANS_STRAIGHT", 15)) {
    /*                    ^                */
#ifdef SR_ANS_STRAIGHT
      *iv_return = SR_ANS_STRAIGHT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "Q_WAIT_FOR_GLUE", 15)) {
    /*                    ^                */
#ifdef Q_WAIT_FOR_GLUE
      *iv_return = Q_WAIT_FOR_GLUE;
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
     ALG_DS_HASH_SHA1 Q_REFERRAL_ERROR Q_RESPONSE_ERROR SR_CRED_AUTH_ADD
     SR_CRED_AUTH_ANS VAL_QUERY_NO_DLV */
  /* Offset 14 gives the best switch position.  */
  switch (name[14]) {
  case 'A':
    if (memEQ(name, "ALG_DS_HASH_SHA1", 16)) {
    /*                             ^        */
#ifdef ALG_DS_HASH_SHA1
      *iv_return = ALG_DS_HASH_SHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "SR_CRED_AUTH_ADD", 16)) {
    /*                             ^        */
#ifdef SR_CRED_AUTH_ADD
      *iv_return = SR_CRED_AUTH_ADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "VAL_QUERY_NO_DLV", 16)) {
    /*                             ^        */
#ifdef VAL_QUERY_NO_DLV
      *iv_return = VAL_QUERY_NO_DLV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "SR_CRED_AUTH_ANS", 16)) {
    /*                             ^        */
#ifdef SR_CRED_AUTH_ANS
      *iv_return = SR_CRED_AUTH_ANS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "Q_REFERRAL_ERROR", 16)) {
    /*                             ^        */
#ifdef Q_REFERRAL_ERROR
      *iv_return = Q_REFERRAL_ERROR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "Q_RESPONSE_ERROR", 16)) {
    /*                             ^        */
#ifdef Q_RESPONSE_ERROR
      *iv_return = Q_RESPONSE_ERROR;
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
     ALG_NSEC3_DSASHA1 ALG_NSEC3_RSASHA1 SHA_DIGEST_LENGTH SR_ANS_BARE_RRSIG
     SR_CRED_AUTH_AUTH */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
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
    break;
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_18 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_DS_HASH_SHA256 VALIDATOR_LOG_PORT VAL_FROM_AUTHORITY */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'H':
    if (memEQ(name, "ALG_DS_HASH_SHA256", 18)) {
    /*                      ^                 */
#ifdef ALG_DS_HASH_SHA256
      *iv_return = ALG_DS_HASH_SHA256;
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
  }
  return PERL_constant_NOTFOUND;
}

static int
constant_19 (pTHX_ const char *name, IV *iv_return) {
  /* When generated this function returned values for the list of names given
     here.  However, subsequent manual editing may have added or removed some.
     ALG_NSEC3_HASH_SHA1 QUERY_BAD_CACHE_TTL SR_CRED_NONAUTH_ADD
     SR_CRED_NONAUTH_ANS VAL_FROM_ADDITIONAL VAL_POL_GOPT_ENABLE
     VAL_QFLAGS_USERMASK VAL_QUERY_USING_DLV */
  /* Offset 5 gives the best switch position.  */
  switch (name[5]) {
  case 'E':
    if (memEQ(name, "SR_CRED_NONAUTH_ADD", 19)) {
    /*                    ^                    */
#ifdef SR_CRED_NONAUTH_ADD
      *iv_return = SR_CRED_NONAUTH_ADD;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "SR_CRED_NONAUTH_ANS", 19)) {
    /*                    ^                    */
#ifdef SR_CRED_NONAUTH_ANS
      *iv_return = SR_CRED_NONAUTH_ANS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'F':
    if (memEQ(name, "VAL_QFLAGS_USERMASK", 19)) {
    /*                    ^                    */
#ifdef VAL_QFLAGS_USERMASK
      *iv_return = VAL_QFLAGS_USERMASK;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "VAL_POL_GOPT_ENABLE", 19)) {
    /*                    ^                    */
#ifdef VAL_POL_GOPT_ENABLE
      *iv_return = VAL_POL_GOPT_ENABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "VAL_FROM_ADDITIONAL", 19)) {
    /*                    ^                    */
#ifdef VAL_FROM_ADDITIONAL
      *iv_return = VAL_FROM_ADDITIONAL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "ALG_NSEC3_HASH_SHA1", 19)) {
    /*                    ^                    */
#ifdef ALG_NSEC3_HASH_SHA1
      *iv_return = ALG_NSEC3_HASH_SHA1;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "VAL_QUERY_USING_DLV", 19)) {
    /*                    ^                    */
#ifdef VAL_QUERY_USING_DLV
      *iv_return = VAL_QUERY_USING_DLV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case '_':
    if (memEQ(name, "QUERY_BAD_CACHE_TTL", 19)) {
    /*                    ^                    */
#ifdef QUERY_BAD_CACHE_TTL
      *iv_return = QUERY_BAD_CACHE_TTL;
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
     MAX_GLUE_FETCH_DEPTH SHA256_DIGEST_LENGTH SR_CRED_NONAUTH_AUTH
     VAL_POL_GOPT_DISABLE */
  /* Offset 17 gives the best switch position.  */
  switch (name[17]) {
  case 'B':
    if (memEQ(name, "VAL_POL_GOPT_DISABLE", 20)) {
    /*                                ^         */
#ifdef VAL_POL_GOPT_DISABLE
      *iv_return = VAL_POL_GOPT_DISABLE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "SHA256_DIGEST_LENGTH", 20)) {
    /*                                ^         */
#ifdef SHA256_DIGEST_LENGTH
      *iv_return = SHA256_DIGEST_LENGTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "MAX_GLUE_FETCH_DEPTH", 20)) {
    /*                                ^         */
#ifdef MAX_GLUE_FETCH_DEPTH
      *iv_return = MAX_GLUE_FETCH_DEPTH;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'U':
    if (memEQ(name, "SR_CRED_NONAUTH_AUTH", 20)) {
    /*                                ^         */
#ifdef SR_CRED_NONAUTH_AUTH
      *iv_return = SR_CRED_NONAUTH_AUTH;
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
     CAN_SIGN_ZONE_AND_KEY Q_CONFLICTING_ANSWERS VAL_POL_GOPT_OVERRIDE */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'N':
    if (memEQ(name, "Q_CONFLICTING_ANSWERS", 21)) {
    /*                   ^                       */
#ifdef Q_CONFLICTING_ANSWERS
      *iv_return = Q_CONFLICTING_ANSWERS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "VAL_POL_GOPT_OVERRIDE", 21)) {
    /*                   ^                       */
#ifdef VAL_POL_GOPT_OVERRIDE
      *iv_return = VAL_POL_GOPT_OVERRIDE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "CAN_SIGN_ZONE_AND_KEY", 21)) {
    /*                   ^                       */
#ifdef CAN_SIGN_ZONE_AND_KEY
      *iv_return = CAN_SIGN_ZONE_AND_KEY;
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
     MAX_ALIAS_CHAIN_LENGTH VAL_QUERY_GLUE_REQUEST VAL_QUERY_NO_AC_DETAIL */
  /* Offset 19 gives the best switch position.  */
  switch (name[19]) {
  case 'A':
    if (memEQ(name, "VAL_QUERY_NO_AC_DETAIL", 22)) {
    /*                                  ^         */
#ifdef VAL_QUERY_NO_AC_DETAIL
      *iv_return = VAL_QUERY_NO_AC_DETAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "VAL_QUERY_GLUE_REQUEST", 22)) {
    /*                                  ^         */
#ifdef VAL_QUERY_GLUE_REQUEST
      *iv_return = VAL_QUERY_GLUE_REQUEST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "MAX_ALIAS_CHAIN_LENGTH", 22)) {
    /*                                  ^         */
#ifdef MAX_ALIAS_CHAIN_LENGTH
      *iv_return = MAX_ALIAS_CHAIN_LENGTH;
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
my @names = (qw(ALG_DH ALG_DSASHA1 ALG_DS_HASH_SHA1 ALG_DS_HASH_SHA256
	       ALG_NSEC3_DSASHA1 ALG_NSEC3_HASH_SHA1 ALG_NSEC3_RSASHA1
	       ALG_RSAMD5 ALG_RSASHA1 CANNOT_BE_USED CAN_SIGN_KEY CAN_SIGN_ZONE
	       CAN_SIGN_ZONE_AND_KEY DNS_PORT EDNS_UDP_SIZE ENVELOPE
	       MAX_ALIAS_CHAIN_LENGTH MAX_GLUE_FETCH_DEPTH
	       QUERY_BAD_CACHE_THRESHOLD QUERY_BAD_CACHE_TTL Q_ANSWERED
	       Q_CONFLICTING_ANSWERS Q_ERROR_BASE Q_INIT Q_MISSING_GLUE
	       Q_QUERY_ERROR Q_REFERRAL_ERROR Q_RESPONSE_ERROR Q_SENT
	       Q_WAIT_FOR_GLUE Q_WRONG_ANSWER RRSIGLABEL SHA256_DIGEST_LENGTH
	       SHA_DIGEST_LENGTH SIGNBY SR_ANS_BARE_RRSIG SR_ANS_CNAME
	       SR_ANS_DNAME SR_ANS_NACK SR_ANS_STRAIGHT SR_ANS_UNSET
	       SR_CRED_AUTH_ADD SR_CRED_AUTH_ANS SR_CRED_AUTH_AUTH SR_CRED_FILE
	       SR_CRED_NONAUTH_ADD SR_CRED_NONAUTH_ANS SR_CRED_NONAUTH_AUTH
	       SR_CRED_UNSET TTL VALIDATOR_LOG_PORT VAL_CTX_IDLEN
	       VAL_FROM_ADDITIONAL VAL_FROM_ANSWER VAL_FROM_AUTHORITY
	       VAL_FROM_QUERY VAL_FROM_UNSET VAL_LOG_OPTIONS
	       VAL_POL_GOPT_DISABLE VAL_POL_GOPT_ENABLE VAL_POL_GOPT_OVERRIDE
	       VAL_QFLAGS_ANY VAL_QFLAGS_USERMASK VAL_QUERY_DONT_VALIDATE
	       VAL_QUERY_GLUE_REQUEST VAL_QUERY_NO_AC_DETAIL VAL_QUERY_NO_DLV
	       VAL_QUERY_USING_DLV VAL_Q_ONLY_MATCHING_FLAGS));

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
  case 8:
    /* Names all of length 8.  */
    /* DNS_PORT ENVELOPE */
    /* Offset 0 gives the best switch position.  */
    switch (*name++) {
    case 'D':
      if (memEQ(name, "NS_PORT", 7)) {
      /*                D             */
#ifdef DNS_PORT
        *iv_return = DNS_PORT;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'E':
      if (memEQ(name, "NVELOPE", 7)) {
      /*                E             */
#ifdef ENVELOPE
        *iv_return = ENVELOPE;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
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
    if (memEQ(name, "VAL_QUERY_DONT_VALIDATE", 23)) {
#ifdef VAL_QUERY_DONT_VALIDATE
      *iv_return = VAL_QUERY_DONT_VALIDATE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 25:
    /* Names all of length 25.  */
    /* QUERY_BAD_CACHE_THRESHOLD VAL_Q_ONLY_MATCHING_FLAGS */
    /* Offset 12 gives the best switch position.  */
    switch (name[12]) {
    case 'A':
      if (memEQ(name, "VAL_Q_ONLY_MATCHING_FLAGS", 25)) {
      /*                           ^                   */
#ifdef VAL_Q_ONLY_MATCHING_FLAGS
        *iv_return = VAL_Q_ONLY_MATCHING_FLAGS;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'C':
      if (memEQ(name, "QUERY_BAD_CACHE_THRESHOLD", 25)) {
      /*                           ^                   */
#ifdef QUERY_BAD_CACHE_THRESHOLD
        *iv_return = QUERY_BAD_CACHE_THRESHOLD;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  }
  return PERL_constant_NOTFOUND;
}

