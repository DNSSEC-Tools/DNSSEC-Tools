dnl Process this file with autoconf to produce a configure script.
dnl

dnl provide it a file to simply check for its existence.
AC_INIT([dnssec-tools], [1.8], [dnssec-tools-users@lists.sourceforge.net])
AC_PREREQ([2.59])

dnl ----------------------------------------------------------------------
dnl catch mis-typed options as early as possible
dnl
AC_ARG_WITH(out-validator,,
         AC_MSG_ERROR([ Invalid option. Use --with-validator/--without-validator instead ]) )
AC_ARG_ENABLE(validator,,
         AC_MSG_ERROR([ Invalid option. Use --with-validator/--without-validator instead ]) )

dnl ----------------------------------------------------------------------
dnl check for programs
dnl
AC_PATH_PROG([PERLPROG],perl)
AC_PATH_PROG(AR, ar)
AC_PATH_PROG(RM, rm)

# allow user to disable bind checks
AC_ARG_ENABLE(bind-checks,
[  --disable-bind-checks   Disable checks for bind dnssec utilities])
if test "x$enable_bind_checks" != "xno"; then
   AC_PATH_PROG(BIND_DNSSEC_KEYGEN, dnssec-keygen)
   if test -z "$BIND_DNSSEC_KEYGEN"; then
     AC_ERROR([Could not locate dnssec-keygen. Please install BIND utilities.])
   fi
   AC_PATH_PROG(BIND_DNSSEC_SIGNZONE, dnssec-signzone)
   if test -z "$BIND_DNSSEC_SIGNZONE"; then
     AC_ERROR([Could not locate dnssec-signzone. Please install BIND utilities.])
   fi
   AC_PATH_PROG(BIND_DNSSEC_CHECKZONE, named-checkzone)
   if test -z "$BIND_DNSSEC_CHECKZONE"; then
     AC_ERROR([Could not locate named-checkzone. Please install BIND utilities.])
   fi
fi
# ? rndc

# libtool info
AC_PROG_LIBTOOL

# useful stuff for installation
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

dnl ----------------------------------------------------------------------
AC_ARG_WITH(validator,
[  --without-validator     Build without libsres, libval and binary apps
                          (Disable if they fail to build on your platform).

   Validator specific options:]
)

if test "x$with_validator" != "xno"; then
  AC_CONFIG_SUBDIRS(validator)
  DNSSEC_SUBDIRS="validator"
  PERLARGS=""
else
  DNSSEC_SUBDIRS="none"
  PERLARGS="NOVALIDATOR"
fi
AC_SUBST(DNSSEC_SUBDIRS)

#
# these are bogus flags for this script but get passed down to validator/config*
#
AC_ARG_WITH(openssl,
[      --with-openssl=PATH     Look for openssl in PATH/{lib,include}.])
AC_ARG_WITH(ipv6,
[      --with-ipv6             Enable IPv6 support.])
AC_ARG_WITH(nsec3,
[      --with-nsec3            Enable nsec3 support.])
AC_ARG_WITH(dlv,
[      --with-dlv              Enable DLV support.])
AC_ARG_WITH(threads,
[      --without-threads       Don't use threads.
])

dnl ----------------------------------------------------------------------
dnl perl specific arguments
dnl
dnl ----------------------------------------------------------------------
if test "x$prefix" = "xNONE" ; then
   # if a default prefix is set then don't change perl's install
   # prefix from what *it* thinks is right, which may not be the
   # default system prefix
   prefix=$ac_default_prefix
else
   # if a prefix was specificied, install everything into the
   # specified prefix, including all perl specific scripts and mans
   # ugh: this likely isn't perfect.

   if test "x$mandir" = "xNONE" ; then
     mandir="$datadir/man"
   fi

   if test "x$exec_prefix" = "xNONE" ; then
     exec_prefix="$prefix"
   fi

   PERLARGS="$PERLARGS INSTALLSCRIPT=$prefix/bin INSTALLSITESCRIPT=$prefix/bin INSTALLBIN=$exec_prefix/bin INSTALLSITEBIN=$exec_prefix/bin INSTALLSITEMAN1DIR=$mandir/man1 INSTALLSITEMAN3DIR=$mandir/man3 INSTALLMAN1DIR=$mandir/man1 INSTALLMAN3DIR=$mandir/man3"
fi

AC_ARG_WITH(perl-build-args,
[  --with-perl-build-args=ARGS Add ARGS to building perl Makefiles.],
	PERLARGS="$PERLARGS $withval"
)
AC_SUBST(PERLARGS)

missing=""
for module in ExtUtils::MakeMaker Net::DNS Net::DNS::SEC Date::Parse
do
   AC_MSG_CHECKING(for perl module $module)

   $PERLPROG "-e 'require $module'" > /dev/null 2>&1
   if test $? -ne 0; then
      AC_MSG_RESULT(no);
      missing="$missing $module"
   else
      AC_MSG_RESULT(ok);
   fi
done
if test -n "$missing" ; then
   AC_MSG_ERROR([Missing required perl modules: $missing])
fi

missing=""
for module in GraphViz Mail::Mailer::sendmail XML::Simple
do
   AC_MSG_CHECKING(for recommended perl module $module)

   $PERLPROG -e "require $module" > /dev/null 2>&1
   if test $? -ne 0; then
      AC_MSG_RESULT(no);
      missing="$missing $module"
   else
      AC_MSG_RESULT(ok);
   fi
done
if test -n "$missing" ; then
   AC_MSG_WARN([Missing recommended perl modules: $missing])
fi

expanded_sysconfdir=`eval echo $sysconfdir`
AC_SUBST(expanded_sysconfdir)

expanded_localstatedir=`eval echo $localstatedir`
AC_SUBST(expanded_localstatedir)

AC_CONFIG_FILES([
 Makefile:Makefile.in
 tools/modules/conf.pm:tools/modules/conf.pm.in
 testing/Makefile:testing/Makefile.in
 dist/rollerd.service:dist/rollerd.service.in
 dist/donutsd.service:dist/donutsd.service.in
])
AC_CONFIG_COMMANDS([default], echo timestamp > stamp-h)
AC_OUTPUT
