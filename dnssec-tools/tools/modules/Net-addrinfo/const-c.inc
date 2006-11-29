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
     AI_ALL AI_IDN NI_IDN */
  /* Offset 4 gives the best switch position.  */
  switch (name[4]) {
  case 'D':
    if (memEQ(name, "AI_IDN", 6)) {
    /*                   ^       */
#ifdef AI_IDN
      *iv_return = AI_IDN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "NI_IDN", 6)) {
    /*                   ^       */
#ifdef NI_IDN
      *iv_return = NI_IDN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "AI_ALL", 6)) {
    /*                   ^       */
#ifdef AI_ALL
      *iv_return = AI_ALL;
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
     EAI_FAIL EAI_INTR GAI_WAIT NI_DGRAM */
  /* Offset 7 gives the best switch position.  */
  switch (name[7]) {
  case 'L':
    if (memEQ(name, "EAI_FAI", 7)) {
    /*                      L     */
#ifdef EAI_FAIL
      *iv_return = EAI_FAIL;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "NI_DGRA", 7)) {
    /*                      M     */
#ifdef NI_DGRAM
      *iv_return = NI_DGRAM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "EAI_INT", 7)) {
    /*                      R     */
#ifdef EAI_INTR
      *iv_return = EAI_INTR;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "GAI_WAI", 7)) {
    /*                      T     */
#ifdef GAI_WAIT
      *iv_return = GAI_WAIT;
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
     EAI_AGAIN NI_NOFQDN */
  /* Offset 0 gives the best switch position.  */
  switch (*name++) {
  case 'E':
    if (memEQ(name, "AI_AGAIN", 8)) {
    /*                E              */
#ifdef EAI_AGAIN
      *iv_return = EAI_AGAIN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "I_NOFQDN", 8)) {
    /*                N              */
#ifdef NI_NOFQDN
      *iv_return = NI_NOFQDN;
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
     AI_PASSIVE EAI_FAMILY EAI_MEMORY EAI_NODATA EAI_NONAME EAI_SYSTEM
     GAI_NOWAIT NI_MAXHOST NI_MAXSERV */
  /* Offset 8 gives the best switch position.  */
  switch (name[8]) {
  case 'E':
    if (memEQ(name, "EAI_SYSTEM", 10)) {
    /*                       ^        */
#ifdef EAI_SYSTEM
      *iv_return = EAI_SYSTEM;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'I':
    if (memEQ(name, "GAI_NOWAIT", 10)) {
    /*                       ^        */
#ifdef GAI_NOWAIT
      *iv_return = GAI_NOWAIT;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'L':
    if (memEQ(name, "EAI_FAMILY", 10)) {
    /*                       ^        */
#ifdef EAI_FAMILY
      *iv_return = EAI_FAMILY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "EAI_NONAME", 10)) {
    /*                       ^        */
#ifdef EAI_NONAME
      *iv_return = EAI_NONAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'R':
    if (memEQ(name, "EAI_MEMORY", 10)) {
    /*                       ^        */
#ifdef EAI_MEMORY
      *iv_return = EAI_MEMORY;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "NI_MAXSERV", 10)) {
    /*                       ^        */
#ifdef NI_MAXSERV
      *iv_return = NI_MAXSERV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "NI_MAXHOST", 10)) {
    /*                       ^        */
#ifdef NI_MAXHOST
      *iv_return = NI_MAXHOST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "EAI_NODATA", 10)) {
    /*                       ^        */
#ifdef EAI_NODATA
      *iv_return = EAI_NODATA;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "AI_PASSIVE", 10)) {
    /*                       ^        */
#ifdef AI_PASSIVE
      *iv_return = AI_PASSIVE;
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
     AI_CANONIDN AI_V4MAPPED EAI_ALLDONE EAI_SERVICE NI_NAMEREQD */
  /* Offset 9 gives the best switch position.  */
  switch (name[9]) {
  case 'C':
    if (memEQ(name, "EAI_SERVICE", 11)) {
    /*                        ^        */
#ifdef EAI_SERVICE
      *iv_return = EAI_SERVICE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'D':
    if (memEQ(name, "AI_CANONIDN", 11)) {
    /*                        ^        */
#ifdef AI_CANONIDN
      *iv_return = AI_CANONIDN;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'E':
    if (memEQ(name, "AI_V4MAPPED", 11)) {
    /*                        ^        */
#ifdef AI_V4MAPPED
      *iv_return = AI_V4MAPPED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'N':
    if (memEQ(name, "EAI_ALLDONE", 11)) {
    /*                        ^        */
#ifdef EAI_ALLDONE
      *iv_return = EAI_ALLDONE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Q':
    if (memEQ(name, "NI_NAMEREQD", 11)) {
    /*                        ^        */
#ifdef NI_NAMEREQD
      *iv_return = NI_NAMEREQD;
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
     AI_CANONNAME EAI_BADFLAGS EAI_CANCELED EAI_OVERFLOW EAI_SOCKTYPE */
  /* Offset 10 gives the best switch position.  */
  switch (name[10]) {
  case 'E':
    if (memEQ(name, "EAI_CANCELED", 12)) {
    /*                         ^        */
#ifdef EAI_CANCELED
      *iv_return = EAI_CANCELED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'G':
    if (memEQ(name, "EAI_BADFLAGS", 12)) {
    /*                         ^        */
#ifdef EAI_BADFLAGS
      *iv_return = EAI_BADFLAGS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'M':
    if (memEQ(name, "AI_CANONNAME", 12)) {
    /*                         ^        */
#ifdef AI_CANONNAME
      *iv_return = AI_CANONNAME;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "EAI_OVERFLOW", 12)) {
    /*                         ^        */
#ifdef EAI_OVERFLOW
      *iv_return = EAI_OVERFLOW;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "EAI_SOCKTYPE", 12)) {
    /*                         ^        */
#ifdef EAI_SOCKTYPE
      *iv_return = EAI_SOCKTYPE;
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
     AI_NUMERICHOST AI_NUMERICSERV EAI_ADDRFAMILY EAI_IDN_ENCODE EAI_INPROGRESS
     NI_NUMERICHOST NI_NUMERICSERV */
  /* Offset 13 gives the best switch position.  */
  switch (name[13]) {
  case 'E':
    if (memEQ(name, "EAI_IDN_ENCOD", 13)) {
    /*                            E      */
#ifdef EAI_IDN_ENCODE
      *iv_return = EAI_IDN_ENCODE;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'S':
    if (memEQ(name, "EAI_INPROGRES", 13)) {
    /*                            S      */
#ifdef EAI_INPROGRESS
      *iv_return = EAI_INPROGRESS;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'T':
    if (memEQ(name, "AI_NUMERICHOS", 13)) {
    /*                            T      */
#ifdef AI_NUMERICHOST
      *iv_return = AI_NUMERICHOST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "NI_NUMERICHOS", 13)) {
    /*                            T      */
#ifdef NI_NUMERICHOST
      *iv_return = NI_NUMERICHOST;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'V':
    if (memEQ(name, "AI_NUMERICSER", 13)) {
    /*                            V      */
#ifdef AI_NUMERICSERV
      *iv_return = AI_NUMERICSERV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    if (memEQ(name, "NI_NUMERICSER", 13)) {
    /*                            V      */
#ifdef NI_NUMERICSERV
      *iv_return = NI_NUMERICSERV;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'Y':
    if (memEQ(name, "EAI_ADDRFAMIL", 13)) {
    /*                            Y      */
#ifdef EAI_ADDRFAMILY
      *iv_return = EAI_ADDRFAMILY;
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
     EAI_NOTCANCELED IPPORT_RESERVED SCOPE_DELIMITER */
  /* Offset 2 gives the best switch position.  */
  switch (name[2]) {
  case 'I':
    if (memEQ(name, "EAI_NOTCANCELED", 15)) {
    /*                 ^                   */
#ifdef EAI_NOTCANCELED
      *iv_return = EAI_NOTCANCELED;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'O':
    if (memEQ(name, "SCOPE_DELIMITER", 15)) {
    /*                 ^                   */
#ifdef SCOPE_DELIMITER
      *iv_return = SCOPE_DELIMITER;
      return PERL_constant_ISIV;
#else
      return PERL_constant_NOTDEF;
#endif
    }
    break;
  case 'P':
    if (memEQ(name, "IPPORT_RESERVED", 15)) {
    /*                 ^                   */
#ifdef IPPORT_RESERVED
      *iv_return = IPPORT_RESERVED;
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
my @names = (qw(AI_ADDRCONFIG AI_ALL AI_CANONIDN AI_CANONNAME AI_IDN
	       AI_IDN_ALLOW_UNASSIGNED AI_IDN_USE_STD3_ASCII_RULES
	       AI_NUMERICHOST AI_NUMERICSERV AI_PASSIVE AI_V4MAPPED
	       EAI_ADDRFAMILY EAI_AGAIN EAI_ALLDONE EAI_BADFLAGS EAI_CANCELED
	       EAI_FAIL EAI_FAMILY EAI_IDN_ENCODE EAI_INPROGRESS EAI_INTR
	       EAI_MEMORY EAI_NODATA EAI_NONAME EAI_NOTCANCELED EAI_OVERFLOW
	       EAI_SERVICE EAI_SOCKTYPE EAI_SYSTEM GAI_NOWAIT GAI_WAIT
	       NI_DGRAM NI_IDN NI_IDN_ALLOW_UNASSIGNED
	       NI_IDN_USE_STD3_ASCII_RULES NI_MAXHOST NI_MAXSERV NI_NAMEREQD
	       NI_NOFQDN NI_NUMERICHOST NI_NUMERICSERV));

print constant_types(); # macro defs
foreach (C_constant ("Netdb", 'constant', 'IV', $types, undef, 3, @names) ) {
    print $_, "\n"; # C constant subs
}
print "#### XS Section:\n";
print XS_constant ("Netdb", $types);
__END__
   */

  switch (len) {
  case 6:
    return constant_6 (aTHX_ name, iv_return);
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
    /* Names all of length 13.  */
    /* AI_ADDRCONFIG NETDB_SUCCESS */
    /* Offset 6 gives the best switch position.  */
    switch (name[6]) {
    case 'R':
      if (memEQ(name, "AI_ADDRCONFIG", 13)) {
      /*                     ^             */
#ifdef AI_ADDRCONFIG
        *iv_return = AI_ADDRCONFIG;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 14:
    return constant_14 (aTHX_ name, iv_return);
    break;
  case 15:
    return constant_15 (aTHX_ name, iv_return);
    break;
  case 23:
    /* Names all of length 23.  */
    /* AI_IDN_ALLOW_UNASSIGNED NI_IDN_ALLOW_UNASSIGNED */
    /* Offset 0 gives the best switch position.  */
    switch (*name++) {
    case 'A':
      if (memEQ(name, "I_IDN_ALLOW_UNASSIGNED", 22)) {
      /*                A                             */
#ifdef AI_IDN_ALLOW_UNASSIGNED
        *iv_return = AI_IDN_ALLOW_UNASSIGNED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'N':
      if (memEQ(name, "I_IDN_ALLOW_UNASSIGNED", 22)) {
      /*                N                             */
#ifdef NI_IDN_ALLOW_UNASSIGNED
        *iv_return = NI_IDN_ALLOW_UNASSIGNED;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    }
    break;
  case 27:
    /* Names all of length 27.  */
    /* AI_IDN_USE_STD3_ASCII_RULES NI_IDN_USE_STD3_ASCII_RULES */
    /* Offset 0 gives the best switch position.  */
    switch (*name++) {
    case 'A':
      if (memEQ(name, "I_IDN_USE_STD3_ASCII_RULES", 26)) {
      /*                A                                 */
#ifdef AI_IDN_USE_STD3_ASCII_RULES
        *iv_return = AI_IDN_USE_STD3_ASCII_RULES;
        return PERL_constant_ISIV;
#else
        return PERL_constant_NOTDEF;
#endif
      }
      break;
    case 'N':
      if (memEQ(name, "I_IDN_USE_STD3_ASCII_RULES", 26)) {
      /*                N                                 */
#ifdef NI_IDN_USE_STD3_ASCII_RULES
        *iv_return = NI_IDN_USE_STD3_ASCII_RULES;
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

