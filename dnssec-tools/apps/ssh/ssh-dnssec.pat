commit a3e226edc51e1cde7e92b99e761c6bd2ddc773e1
Author: Robert Story <rstory@localhost>
Date:   Thu May 17 23:30:28 2012

    DNSSEC-Tools local validation patch

diff --git a/config.h.in b/config.h.in
index 60d0c65..860dca4 100644
--- a/config.h.in
+++ b/config.h.in
@@ -125,6 +125,9 @@
 /* Define if you don't want to use wtmpx */
 #undef DISABLE_WTMPX
 
+/* Define if you want local DNSSEC validation support */
+#undef DNSSEC_LOCAL_VALIDATION
+
 /* Enable for PKCS#11 support */
 #undef ENABLE_PKCS11
 
@@ -587,9 +590,15 @@
 /* Define to 1 if you have the `pam' library (-lpam). */
 #undef HAVE_LIBPAM
 
+/* Define to 1 if you have the `pthread' library (-lpthread). */
+#undef HAVE_LIBPTHREAD
+
 /* Define to 1 if you have the `socket' library (-lsocket). */
 #undef HAVE_LIBSOCKET
 
+/* Define to 1 if you have the `sres' library (-lsres). */
+#undef HAVE_LIBSRES
+
 /* Define to 1 if you have the <libutil.h> header file. */
 #undef HAVE_LIBUTIL_H
 
@@ -1182,6 +1191,9 @@
 /* define if you have u_intxx_t data type */
 #undef HAVE_U_INTXX_T
 
+/* Define to 1 if you have the <validator/validator.h> header file. */
+#undef HAVE_VALIDATOR_VALIDATOR_H
+
 /* Define to 1 if you have the `vasprintf' function. */
 #undef HAVE_VASPRINTF
 
diff --git a/configure b/configure
index 035b6f0..c732242 100755
--- a/configure
+++ b/configure
@@ -733,6 +733,7 @@ with_prngd_socket
 with_pam
 with_privsep_user
 with_sandbox
+with_local_dnssec_validation
 with_selinux
 with_kerberos5
 with_privsep_path
@@ -1423,6 +1424,7 @@ Optional Packages:
   --with-pam              Enable PAM support
   --with-privsep-user=user Specify non-privileged user for privilege separation
   --with-sandbox=style    Specify privilege separation sandbox (no, darwin, rlimit, systrace, seccomp_filter)
+  --with-local-dnssec-validation Enable local DNSSEC validation using libval
   --with-selinux          Enable SELinux support
   --with-kerberos5=PATH   Enable Kerberos 5 support
   --with-privsep-path=xxx Path for privilege separation chroot (default=/var/empty)
@@ -14537,6 +14539,265 @@ $as_echo "#define HAVE_SYS_NERR 1" >>confdefs.h
 
 fi
 
+LIBVAL_MSG="no"
+# Check whether user wants DNSSEC local validation support
+
+# Check whether --with-local-dnssec-validation was given.
+if test "${with_local_dnssec_validation+set}" = set; then :
+  withval=$with_local_dnssec_validation;  if test "x$withval" != "xno" ; then
+ 		if test "x$withval" != "xyes" ; then
+			CPPFLAGS="$CPPFLAGS -I${withval}"
+			LDFLAGS="$LDFLAGS -L${withval}"
+			if test ! -z "$need_dash_r" ; then
+				LDFLAGS="$LDFLAGS -R${withval}"
+ 		fi
+			if test ! -z "$blibpath" ; then
+				blibpath="$blibpath:${withval}"
+ 		fi
+ 	    fi
+		for ac_header in validator/validator.h
+do :
+  ac_fn_c_check_header_mongrel "$LINENO" "validator/validator.h" "ac_cv_header_validator_validator_h" "$ac_includes_default"
+if test "x$ac_cv_header_validator_validator_h" = xyes; then :
+  cat >>confdefs.h <<_ACEOF
+#define HAVE_VALIDATOR_VALIDATOR_H 1
+_ACEOF
+
+fi
+
+done
+
+		if test "$ac_cv_header_validator_validator_h" != yes; then
+			as_fn_error $? "Cannot find validator.h" "$LINENO" 5
+		fi
+		{ $as_echo "$as_me:${as_lineno-$LINENO}: checking for query_send in -lsres" >&5
+$as_echo_n "checking for query_send in -lsres... " >&6; }
+if ${ac_cv_lib_sres_query_send+:} false; then :
+  $as_echo_n "(cached) " >&6
+else
+  ac_check_lib_save_LIBS=$LIBS
+LIBS="-lsres  $LIBS"
+cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+
+/* Override any GCC internal prototype to avoid an error.
+   Use char because int might match the return type of a GCC
+   builtin and then its argument prototype would still apply.  */
+#ifdef __cplusplus
+extern "C"
+#endif
+char query_send ();
+int
+main ()
+{
+return query_send ();
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_link "$LINENO"; then :
+  ac_cv_lib_sres_query_send=yes
+else
+  ac_cv_lib_sres_query_send=no
+fi
+rm -f core conftest.err conftest.$ac_objext \
+    conftest$ac_exeext conftest.$ac_ext
+LIBS=$ac_check_lib_save_LIBS
+fi
+{ $as_echo "$as_me:${as_lineno-$LINENO}: result: $ac_cv_lib_sres_query_send" >&5
+$as_echo "$ac_cv_lib_sres_query_send" >&6; }
+if test "x$ac_cv_lib_sres_query_send" = xyes; then :
+  cat >>confdefs.h <<_ACEOF
+#define HAVE_LIBSRES 1
+_ACEOF
+
+  LIBS="-lsres $LIBS"
+
+fi
+
+		if test "$ac_cv_lib_sres_query_send" != yes; then
+			as_fn_error $? "Cannot find libsres" "$LINENO" 5
+		fi
+		LIBVAL_SUFFIX=""
+		{ $as_echo "$as_me:${as_lineno-$LINENO}: checking for p_val_status in -lval" >&5
+$as_echo_n "checking for p_val_status in -lval... " >&6; }
+if ${ac_cv_lib_val_p_val_status+:} false; then :
+  $as_echo_n "(cached) " >&6
+else
+  ac_check_lib_save_LIBS=$LIBS
+LIBS="-lval  $LIBS"
+cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+
+/* Override any GCC internal prototype to avoid an error.
+   Use char because int might match the return type of a GCC
+   builtin and then its argument prototype would still apply.  */
+#ifdef __cplusplus
+extern "C"
+#endif
+char p_val_status ();
+int
+main ()
+{
+return p_val_status ();
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_link "$LINENO"; then :
+  ac_cv_lib_val_p_val_status=yes
+else
+  ac_cv_lib_val_p_val_status=no
+fi
+rm -f core conftest.err conftest.$ac_objext \
+    conftest$ac_exeext conftest.$ac_ext
+LIBS=$ac_check_lib_save_LIBS
+fi
+{ $as_echo "$as_me:${as_lineno-$LINENO}: result: $ac_cv_lib_val_p_val_status" >&5
+$as_echo "$ac_cv_lib_val_p_val_status" >&6; }
+if test "x$ac_cv_lib_val_p_val_status" = xyes; then :
+  LIBS="$LIBS -lval"
+else
+   { $as_echo "$as_me:${as_lineno-$LINENO}: checking for pthread_rwlock_init in -lpthread" >&5
+$as_echo_n "checking for pthread_rwlock_init in -lpthread... " >&6; }
+if ${ac_cv_lib_pthread_pthread_rwlock_init+:} false; then :
+  $as_echo_n "(cached) " >&6
+else
+  ac_check_lib_save_LIBS=$LIBS
+LIBS="-lpthread  $LIBS"
+cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+
+/* Override any GCC internal prototype to avoid an error.
+   Use char because int might match the return type of a GCC
+   builtin and then its argument prototype would still apply.  */
+#ifdef __cplusplus
+extern "C"
+#endif
+char pthread_rwlock_init ();
+int
+main ()
+{
+return pthread_rwlock_init ();
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_link "$LINENO"; then :
+  ac_cv_lib_pthread_pthread_rwlock_init=yes
+else
+  ac_cv_lib_pthread_pthread_rwlock_init=no
+fi
+rm -f core conftest.err conftest.$ac_objext \
+    conftest$ac_exeext conftest.$ac_ext
+LIBS=$ac_check_lib_save_LIBS
+fi
+{ $as_echo "$as_me:${as_lineno-$LINENO}: result: $ac_cv_lib_pthread_pthread_rwlock_init" >&5
+$as_echo "$ac_cv_lib_pthread_pthread_rwlock_init" >&6; }
+if test "x$ac_cv_lib_pthread_pthread_rwlock_init" = xyes; then :
+  cat >>confdefs.h <<_ACEOF
+#define HAVE_LIBPTHREAD 1
+_ACEOF
+
+  LIBS="-lpthread $LIBS"
+
+fi
+
+			  { $as_echo "$as_me:${as_lineno-$LINENO}: checking for p_val_status in -lval-threads" >&5
+$as_echo_n "checking for p_val_status in -lval-threads... " >&6; }
+if ${ac_cv_lib_val_threads_p_val_status+:} false; then :
+  $as_echo_n "(cached) " >&6
+else
+  ac_check_lib_save_LIBS=$LIBS
+LIBS="-lval-threads  $LIBS"
+cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+
+/* Override any GCC internal prototype to avoid an error.
+   Use char because int might match the return type of a GCC
+   builtin and then its argument prototype would still apply.  */
+#ifdef __cplusplus
+extern "C"
+#endif
+char p_val_status ();
+int
+main ()
+{
+return p_val_status ();
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_link "$LINENO"; then :
+  ac_cv_lib_val_threads_p_val_status=yes
+else
+  ac_cv_lib_val_threads_p_val_status=no
+fi
+rm -f core conftest.err conftest.$ac_objext \
+    conftest$ac_exeext conftest.$ac_ext
+LIBS=$ac_check_lib_save_LIBS
+fi
+{ $as_echo "$as_me:${as_lineno-$LINENO}: result: $ac_cv_lib_val_threads_p_val_status" >&5
+$as_echo "$ac_cv_lib_val_threads_p_val_status" >&6; }
+if test "x$ac_cv_lib_val_threads_p_val_status" = xyes; then :
+   LIBS="$LIBS -lval-threads -lpthread"
+				  LIBVAL_SUFFIX="-threads"
+else
+  as_fn_error $? "Cannot find libval or libval-threads" "$LINENO" 5
+fi
+
+
+fi
+
+		{ $as_echo "$as_me:${as_lineno-$LINENO}: checking for res_query in -lresolv" >&5
+$as_echo_n "checking for res_query in -lresolv... " >&6; }
+if ${ac_cv_lib_resolv_res_query+:} false; then :
+  $as_echo_n "(cached) " >&6
+else
+  ac_check_lib_save_LIBS=$LIBS
+LIBS="-lresolv  $LIBS"
+cat confdefs.h - <<_ACEOF >conftest.$ac_ext
+/* end confdefs.h.  */
+
+/* Override any GCC internal prototype to avoid an error.
+   Use char because int might match the return type of a GCC
+   builtin and then its argument prototype would still apply.  */
+#ifdef __cplusplus
+extern "C"
+#endif
+char res_query ();
+int
+main ()
+{
+return res_query ();
+  ;
+  return 0;
+}
+_ACEOF
+if ac_fn_c_try_link "$LINENO"; then :
+  ac_cv_lib_resolv_res_query=yes
+else
+  ac_cv_lib_resolv_res_query=no
+fi
+rm -f core conftest.err conftest.$ac_objext \
+    conftest$ac_exeext conftest.$ac_ext
+LIBS=$ac_check_lib_save_LIBS
+fi
+{ $as_echo "$as_me:${as_lineno-$LINENO}: result: $ac_cv_lib_resolv_res_query" >&5
+$as_echo "$ac_cv_lib_resolv_res_query" >&6; }
+if test "x$ac_cv_lib_resolv_res_query" = xyes; then :
+  LIBS="$LIBS -lresolv"
+fi
+
+
+$as_echo "#define DNSSEC_LOCAL_VALIDATION 1" >>confdefs.h
+
+		LIBVAL_MSG="yes, libval${LIBVAL_SUFFIX}"
+	fi
+
+fi
+
+
 # Check libraries needed by DNS fingerprint support
 { $as_echo "$as_me:${as_lineno-$LINENO}: checking for library containing getrrsetbyname" >&5
 $as_echo_n "checking for library containing getrrsetbyname... " >&6; }
@@ -17930,6 +18191,7 @@ echo "              MD5 password support: $MD5_MSG"
 echo "                   libedit support: $LIBEDIT_MSG"
 echo "  Solaris process contract support: $SPC_MSG"
 echo "           Solaris project support: $SP_MSG"
+echo "   Local DNSSEC validation support: $LIBVAL_MSG"
 echo "       IP address in \$DISPLAY hack: $DISPLAY_HACK_MSG"
 echo "           Translate v4 in v6 hack: $IPV4_IN6_HACK_MSG"
 echo "                  BSD Auth support: $BSD_AUTH_MSG"
diff --git a/configure.ac b/configure.ac
index 1457b8a..7a6b78b 100644
--- a/configure.ac
+++ b/configure.ac
@@ -3389,6 +3389,44 @@ if test "x$ac_cv_libc_defines_sys_nerr" = "xyes" ; then
 	AC_DEFINE([HAVE_SYS_NERR], [1], [Define if your system defines sys_nerr])
 fi
 
+LIBVAL_MSG="no"
+# Check whether user wants DNSSEC local validation support
+AC_ARG_WITH(local-dnssec-validation,
+	[  --with-local-dnssec-validation Enable local DNSSEC validation using libval],
+	[ if test "x$withval" != "xno" ; then
+ 		if test "x$withval" != "xyes" ; then
+			CPPFLAGS="$CPPFLAGS -I${withval}"
+			LDFLAGS="$LDFLAGS -L${withval}"
+			if test ! -z "$need_dash_r" ; then
+				LDFLAGS="$LDFLAGS -R${withval}"
+ 		fi
+			if test ! -z "$blibpath" ; then
+				blibpath="$blibpath:${withval}"
+ 		fi
+ 	    fi
+		AC_CHECK_HEADERS(validator/validator.h)
+		if test "$ac_cv_header_validator_validator_h" != yes; then
+			AC_MSG_ERROR(Cannot find validator.h)
+		fi
+		AC_CHECK_LIB(sres, query_send)
+		if test "$ac_cv_lib_sres_query_send" != yes; then
+			AC_MSG_ERROR(Cannot find libsres)
+		fi
+		LIBVAL_SUFFIX=""
+		AC_CHECK_LIB(val, p_val_status,LIBS="$LIBS -lval",
+			[ AC_CHECK_LIB(pthread, pthread_rwlock_init)
+			  AC_CHECK_LIB(val-threads, p_val_status,
+				[ LIBS="$LIBS -lval-threads -lpthread"
+				  LIBVAL_SUFFIX="-threads"],
+				AC_MSG_ERROR(Cannot find libval or libval-threads))
+			])
+		AC_CHECK_LIB(resolv, res_query,LIBS="$LIBS -lresolv")
+		AC_DEFINE(DNSSEC_LOCAL_VALIDATION, 1,
+			[Define if you want local DNSSEC validation support])
+		LIBVAL_MSG="yes, libval${LIBVAL_SUFFIX}"
+	fi
+        ])
+
 # Check libraries needed by DNS fingerprint support
 AC_SEARCH_LIBS([getrrsetbyname], [resolv],
 	[AC_DEFINE([HAVE_GETRRSETBYNAME], [1],
@@ -4345,6 +4383,7 @@ echo "              MD5 password support: $MD5_MSG"
 echo "                   libedit support: $LIBEDIT_MSG"
 echo "  Solaris process contract support: $SPC_MSG"
 echo "           Solaris project support: $SP_MSG"
+echo "   Local DNSSEC validation support: $LIBVAL_MSG"
 echo "       IP address in \$DISPLAY hack: $DISPLAY_HACK_MSG"
 echo "           Translate v4 in v6 hack: $IPV4_IN6_HACK_MSG"
 echo "                  BSD Auth support: $BSD_AUTH_MSG"
diff --git a/dns.c b/dns.c
index 131cb3d..64e917a 100644
--- a/dns.c
+++ b/dns.c
@@ -35,6 +35,10 @@
 #include <stdio.h>
 #include <string.h>
 
+#ifdef DNSSEC_LOCAL_VALIDATION
+# include <validator/validator.h>
+#endif
+
 #include "xmalloc.h"
 #include "key.h"
 #include "dns.h"
@@ -177,7 +181,11 @@ verify_host_key_dns(const char *hostname, struct sockaddr *address,
 {
 	u_int counter;
 	int result;
+#ifndef DNSSEC_LOCAL_VALIDATION
 	struct rrsetinfo *fingerprints = NULL;
+#else
+	struct val_result_chain *val_res, *val_results = NULL;
+#endif
 
 	u_int8_t hostkey_algorithm;
 	u_int8_t hostkey_digest_type;
@@ -200,6 +208,7 @@ verify_host_key_dns(const char *hostname, struct sockaddr *address,
 		return -1;
 	}
 
+#ifndef DNSSEC_LOCAL_VALIDATION
 	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
 	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
 	if (result) {
@@ -208,7 +217,7 @@ verify_host_key_dns(const char *hostname, struct sockaddr *address,
 	}
 
 	if (fingerprints->rri_flags & RRSET_VALIDATED) {
-		*flags |= DNS_VERIFY_SECURE;
+		*flags |= (DNS_VERIFY_SECURE|DNS_VERIFY_TRUSTED);
 		debug("found %d secure fingerprints in DNS",
 		    fingerprints->rri_nrdatas);
 	} else {
@@ -257,6 +266,90 @@ verify_host_key_dns(const char *hostname, struct sockaddr *address,
 	xfree(hostkey_digest); /* from key_fingerprint_raw() */
 	freerrset(fingerprints);
 
+#else /* DNSSEC_LOCAL_VALIDATION */
+
+	result = val_resolve_and_check(NULL, hostname, DNS_RDATACLASS_IN,
+	    DNS_RDATATYPE_SSHFP, 0, &val_results);
+	if (result != VAL_NO_ERROR){
+		verbose("DNS lookup error: %s", p_ac_status(val_results->val_rc_status));
+		return -1;
+	}
+
+	/* Initialize host key parameters */
+	if (!dns_read_key(&hostkey_algorithm, &hostkey_digest_type,
+	    &hostkey_digest, &hostkey_digest_len, hostkey)) {
+		error("Error calculating host key fingerprint.");
+		val_free_result_chain(val_results);
+		return -1;
+	}
+
+	counter = 0;
+	for (val_res = val_results; val_res; val_res = val_res->val_rc_next)  {
+		struct val_rrset_rec *val_rrset;
+		struct val_rr_rec *rr;
+
+		val_rrset = val_res->val_rc_rrset;
+		if ((NULL == val_rrset) || (NULL == val_rrset->val_rrset_data)) 
+			continue;
+
+		for(rr = val_rrset->val_rrset_data; rr;
+		    rr = rr->rr_next) {
+
+			if (NULL == rr->rr_rdata)
+				continue;
+
+			/*
+			 * Extract the key from the answer. Ignore any badly
+			 * formatted fingerprints.
+			 */
+			if (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
+			    &dnskey_digest, &dnskey_digest_len,
+			    rr->rr_rdata,
+			    rr->rr_rdata_length)) {
+				verbose("Error parsing fingerprint from DNS.");
+				continue;
+			}
+
+			++counter;
+
+			/* Check if the current key is the same as the given key */
+			if (hostkey_algorithm == dnskey_algorithm &&
+			    hostkey_digest_type == dnskey_digest_type) {
+				if (hostkey_digest_len == dnskey_digest_len &&
+				    memcmp(hostkey_digest, dnskey_digest,
+				    hostkey_digest_len) == 0) {
+					debug("found matching fingerprints in DNS");
+					*flags |= DNS_VERIFY_MATCH;
+				}
+			}
+			xfree(dnskey_digest);
+		}
+	    if (val_istrusted(val_res->val_rc_status)) {
+		    /*
+		     * local validation can result in a non-secure, but trusted
+		     * response. For example, in a corporate network the authoritative
+		     * server for internal DNS may be on the internal network, behind
+		     * a firewall. Local validation policy can be configured to trust
+		     * these results without using DNSSEC to validate them.
+		     */
+		    *flags |= DNS_VERIFY_TRUSTED;
+		    if (val_isvalidated(val_res->val_rc_status)) {
+			    *flags |= DNS_VERIFY_SECURE;
+			    debug("found %d trusted fingerprints in DNS", counter);
+		    } else  {
+			    debug("found %d trusted, but not validated, fingerprints in DNS", counter);
+		    }
+	    } else {
+		    debug("found %d un-trusted fingerprints in DNS", counter);
+	    }
+	}
+	if(counter)
+		*flags |= DNS_VERIFY_FOUND;
+
+	xfree(hostkey_digest); /* from key_fingerprint_raw() */
+	val_free_result_chain(val_results);
+#endif /* DNSSEC_LOCAL_VALIDATION */
+
 	if (*flags & DNS_VERIFY_FOUND)
 		if (*flags & DNS_VERIFY_MATCH)
 			debug("matching host key fingerprint found in DNS");
diff --git a/dns.h b/dns.h
index 90cfd7b..0b0eeab 100644
--- a/dns.h
+++ b/dns.h
@@ -45,6 +45,7 @@ enum sshfp_hashes {
 #define DNS_VERIFY_FOUND	0x00000001
 #define DNS_VERIFY_MATCH	0x00000002
 #define DNS_VERIFY_SECURE	0x00000004
+#define DNS_VERIFY_TRUSTED	0x00000008
 
 int	verify_host_key_dns(const char *, struct sockaddr *, Key *, int *);
 int	export_dns_rr(const char *, Key *, FILE *, int);
diff --git a/readconf.c b/readconf.c
index 097bb05..fc7b2fb 100644
--- a/readconf.c
+++ b/readconf.c
@@ -134,6 +134,7 @@ typedef enum {
 	oHashKnownHosts,
 	oTunnel, oTunnelDevice, oLocalCommand, oPermitLocalCommand,
 	oVisualHostKey, oUseRoaming, oZeroKnowledgePasswordAuthentication,
+        oStrictDnssecChecking, oAutoAnswerValidatedKeys,
 	oKexAlgorithms, oIPQoS, oRequestTTY,
 	oDeprecated, oUnsupported
 } OpCodes;
@@ -243,6 +244,13 @@ static struct {
 #else
 	{ "zeroknowledgepasswordauthentication", oUnsupported },
 #endif
+#ifdef DNSSEC_LOCAL_VALIDATION
+        { "strictdnssecchecking", oStrictDnssecChecking },
+        { "autoanswervalidatedkeys", oAutoAnswerValidatedKeys },
+#else
+        { "strictdnssecchecking", oUnsupported },
+        { "autoanswervalidatedkeys", oUnsupported },
+#endif
 	{ "kexalgorithms", oKexAlgorithms },
 	{ "ipqos", oIPQoS },
 	{ "requesttty", oRequestTTY },
@@ -519,6 +527,14 @@ parse_yesnoask:
 			*intptr = value;
 		break;
 
+	case oStrictDnssecChecking:
+		intptr = &options->strict_dnssec_checking;
+                goto parse_yesnoask;
+
+	case oAutoAnswerValidatedKeys:
+		intptr = &options->autoanswer_validated_keys;
+                goto parse_yesnoask;
+
 	case oCompression:
 		intptr = &options->compression;
 		goto parse_flag;
@@ -1148,6 +1164,8 @@ initialize_options(Options * options)
 	options->batch_mode = -1;
 	options->check_host_ip = -1;
 	options->strict_host_key_checking = -1;
+	options->strict_dnssec_checking = -1;
+        options->autoanswer_validated_keys = -1;
 	options->compression = -1;
 	options->tcp_keep_alive = -1;
 	options->compression_level = -1;
@@ -1255,6 +1273,10 @@ fill_default_options(Options * options)
 		options->check_host_ip = 1;
 	if (options->strict_host_key_checking == -1)
 		options->strict_host_key_checking = 2;	/* 2 is default */
+	if (options->strict_dnssec_checking == -1)
+		options->strict_dnssec_checking = 2;	/* 2 is default */
+	if (options->autoanswer_validated_keys == -1)
+		options->autoanswer_validated_keys = 0;	/* 0 is default */
 	if (options->compression == -1)
 		options->compression = 0;
 	if (options->tcp_keep_alive == -1)
diff --git a/readconf.h b/readconf.h
index be30ee0..2b22d06 100644
--- a/readconf.h
+++ b/readconf.h
@@ -134,6 +134,9 @@ typedef struct {
 
 	int	use_roaming;
 
+	int     strict_dnssec_checking;	/* Strict DNSSEC checking. */
+	int     autoanswer_validated_keys;
+
 	int	request_tty;
 }       Options;
 
diff --git a/sshconnect.c b/sshconnect.c
index 0ee7266..efa509c 100644
--- a/sshconnect.c
+++ b/sshconnect.c
@@ -26,6 +26,10 @@
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
+#ifdef DNSSEC_LOCAL_VALIDATION
+# include <validator/validator.h>
+#endif
+
 #include <ctype.h>
 #include <errno.h>
 #include <fcntl.h>
@@ -66,6 +70,9 @@ char *client_version_string = NULL;
 char *server_version_string = NULL;
 
 static int matching_host_key_dns = 0;
+#ifdef DNSSEC_LOCAL_VALIDATION
+static int validated_host_key_dns = 0;
+#endif
 
 static pid_t proxy_command_pid = 0;
 
@@ -77,6 +84,7 @@ extern uid_t original_effective_uid;
 
 static int show_other_keys(struct hostkeys *, Key *);
 static void warn_changed_key(Key *);
+static int confirm(const char *prompt);
 
 /*
  * Connect to the given ssh server using a proxy command.
@@ -342,7 +350,11 @@ ssh_connect(const char *host, struct sockaddr_storage * hostaddr,
 	int on = 1;
 	int sock = -1, attempt;
 	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
-	struct addrinfo hints, *ai, *aitop;
+	struct addrinfo hints;
+	struct addrinfo *ai, *aitop = NULL;
+#ifdef DNSSEC_LOCAL_VALIDATION
+	val_status_t val_status;
+#endif
 
 	debug2("ssh_connect: needpriv %d", needpriv);
 
@@ -356,9 +368,59 @@ ssh_connect(const char *host, struct sockaddr_storage * hostaddr,
 	hints.ai_family = family;
 	hints.ai_socktype = SOCK_STREAM;
 	snprintf(strport, sizeof strport, "%u", port);
+#ifndef DNSSEC_LOCAL_VALIDATION
 	if ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0)
 		fatal("%s: Could not resolve hostname %.100s: %s", __progname,
 		    host, ssh_gai_strerror(gaierr));
+#else
+	gaierr = val_getaddrinfo(NULL, host, strport, &hints, &aitop,
+                                 &val_status);
+        debug2("ssh_connect: gaierr %d, val_status %d / %s; trusted: %d",
+               gaierr, val_status, p_val_status(val_status),
+               val_istrusted(val_status));
+	if (gaierr != 0) {
+            if (VAL_GETADDRINFO_HAS_STATUS(gaierr) &&
+                !val_istrusted(val_status)) {
+                error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+                error("@ WARNING: UNTRUSTED ERROR IN DNS RESOLUTION FOR HOST!    @");
+                error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+                error("The authenticity of DNS response is not trusted (%s).", 
+                      p_val_status(val_status));
+            }
+		fatal("%s: Could not resolve hostname %.100s: %s", __progname,
+		    host, ssh_gai_strerror(gaierr));
+        }
+ 	if (!val_istrusted(val_status)) {
+            error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+            error("@ WARNING: UNTRUSTED DNS RESOLUTION FOR HOST IP ADRRESS! @");
+            error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+            error("The authenticity of DNS data for the host '%.200s' "
+                  "can't be established.", host);
+            if (options.strict_dnssec_checking == 1) {
+                fatal("DNS resolution is not trusted (%s) "
+                      "and you have requested strict checking",
+                      p_val_status(val_status));
+            } else if (options.strict_dnssec_checking == 2) {
+                char msg[1024];
+                for (ai = aitop; ai; ai = ai->ai_next) {
+                    if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
+                        continue;
+                    if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
+                            ntop, sizeof(ntop), strport, sizeof(strport),
+                            NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
+                        error("ssh_connect: getnameinfo failed");
+                        continue;
+                    }
+                    error(" IP address %s port %s", ntop, strport);
+                }
+                snprintf(msg,sizeof(msg),
+                         "Are you sure you want to attempt to connect "
+                         "(yes/no)? ");
+                if (!confirm(msg)) 
+                    return (-1);
+            }
+ 	}
+#endif /* DNSSEC_LOCAL_VALIDATION */
 
 	for (attempt = 0; attempt < connection_attempts; attempt++) {
 		if (attempt > 0) {
@@ -814,6 +876,7 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 		}
 		break;
 	case HOST_NEW:
+		debug("Host '%.200s' new.", host);
 		if (options.host_key_alias == NULL && port != 0 &&
 		    port != SSH_DEFAULT_PORT) {
 			debug("checking without port identifier");
@@ -860,6 +923,17 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 					    "No matching host key fingerprint"
 					    " found in DNS.\n");
 			}
+#ifdef DNSSEC_LOCAL_VALIDATION
+                        if (options.autoanswer_validated_keys &&
+                            validated_host_key_dns && matching_host_key_dns) {
+                            snprintf(msg, sizeof(msg),
+                                     "The authenticity of host '%.200s (%s)' was "
+                                     " validated via DNSSEC%s",
+                                     host, ip, msg1);
+                            logit(msg);
+                            xfree(fp);
+                        } else {
+#endif
 			snprintf(msg, sizeof(msg),
 			    "The authenticity of host '%.200s (%s)' can't be "
 			    "established%s\n"
@@ -874,6 +948,9 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 			xfree(fp);
 			if (!confirm(msg))
 				goto fail;
+#ifdef DNSSEC_LOCAL_VALIDATION
+                        }
+#endif
 		}
 		/*
 		 * If not in strict mode, add the key automatically to the
@@ -948,6 +1025,8 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 				key_msg = "is unchanged";
 			else
 				key_msg = "has a different value";
+#ifdef DNSSEC_LOCAL_VALIDATION
+                        if (!validated_host_key_dns) {
 			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
 			error("@       WARNING: POSSIBLE DNS SPOOFING DETECTED!          @");
 			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
@@ -956,6 +1035,19 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 			error("%s. This could either mean that", key_msg);
 			error("DNS SPOOFING is happening or the IP address for the host");
 			error("and its host key have changed at the same time.");
+                        }
+                        else {
+#endif
+			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+			error("@       WARNING: HOST IP ADDRESS HAS CHANGED!             @");
+			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+                        error("The %s host key for %s has changed,", type, host);
+			error("and the key for the according IP address %s", ip);
+			error("%s. The IP address for the host", key_msg);
+			error("and its host key have changed at the same time.");
+#ifdef DNSSEC_LOCAL_VALIDATION
+                        }
+#endif
 			if (ip_status != HOST_NEW)
 				error("Offending key for IP in %s:%lu",
 				    ip_found->file, ip_found->line);
@@ -971,11 +1063,53 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 		 * If strict host key checking is in use, the user will have
 		 * to edit the key manually and we can only abort.
 		 */
+#ifdef DNSSEC_LOCAL_VALIDATION
+		if ((options.strict_host_key_checking == 2) &&
+                    options.autoanswer_validated_keys &&
+                    matching_host_key_dns && validated_host_key_dns) {
+                    logit("The authenticity of host '%.200s (%s)' was "
+                          " validated via DNSSEC.",
+                          host, ip);
+                    /*
+                     * If not in strict mode, add the key automatically to the
+                     * local known_hosts file.
+                     */
+                    if (options.check_host_ip && ip_status == HOST_NEW) {
+			snprintf(hostline, sizeof(hostline), "%s,%s",
+                                 host, ip);
+			hostp = hostline;
+			if (options.hash_known_hosts) {
+                            /* Add hash of host and IP separately */
+                            r = add_host_to_hostfile(user_hostfiles[0], host,
+                                                     host_key, options.hash_known_hosts) &&
+                                add_host_to_hostfile(user_hostfiles[0], ip,
+                                                     host_key, options.hash_known_hosts);
+			} else {
+                            /* Add unhashed "host,ip" */
+                            r = add_host_to_hostfile(user_hostfiles[0],
+                                                     hostline, host_key,
+                                                     options.hash_known_hosts);
+			}
+                    } else {
+			r = add_host_to_hostfile(user_hostfiles[0], host, host_key,
+                                                 options.hash_known_hosts);
+			hostp = host;
+                    }
+                    
+                    if (!r)
+			logit("Failed to add the host to the list of known "
+                              "hosts (%.500s).", user_hostfiles[0]);
+                    else
+			logit("Warning: Permanently added '%.200s' (%s) to the "
+                              "list of known hosts.", hostp, type);
+                }
+                else
+#endif
 		if (options.strict_host_key_checking) {
 			error("%s host key for %.200s has changed and you have "
 			    "requested strict checking.", type, host);
 			goto fail;
-		}
+		} else {
 
  continue_unsafe:
 		/*
@@ -1039,6 +1173,7 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 		 * by that sentence, and ask the user if he/she wishes to
 		 * accept the authentication.
 		 */
+                }
 		break;
 	case HOST_FOUND:
 		fatal("internal error");
@@ -1063,10 +1198,19 @@ check_host_key(char *hostname, struct sockaddr *hostaddr, u_short port,
 			error("Exiting, you have requested strict checking.");
 			goto fail;
 		} else if (options.strict_host_key_checking == 2) {
+#ifdef DNSSEC_LOCAL_VALIDATION
+                    if (options.autoanswer_validated_keys &&
+                        matching_host_key_dns && validated_host_key_dns) {
+			logit("%s", msg);
+                    } else {
+#endif
 			strlcat(msg, "\nAre you sure you want "
 			    "to continue connecting (yes/no)? ", sizeof(msg));
 			if (!confirm(msg))
 				goto fail;
+#ifdef DNSSEC_LOCAL_VALIDATION
+                    }
+#endif
 		} else {
 			logit("%s", msg);
 		}
@@ -1118,12 +1262,44 @@ verify_host_key(char *host, struct sockaddr *hostaddr, Key *host_key)
 	/* XXX certs are not yet supported for DNS */
 	if (!key_is_cert(host_key) && options.verify_host_key_dns &&
 	    verify_host_key_dns(host, hostaddr, host_key, &flags) == 0) {
+
+#ifdef DNSSEC_LOCAL_VALIDATION
+		/*
+		 * local validation can result in a non-secure, but trusted
+		 * response. For example, in a corporate network the authoritative
+		 * server for internal DNS may be on the internal network, behind
+		 * a firewall. Local validation policy can be configured to trust
+		 * these results without using DNSSEC to validate them.
+		 */
+		if (!(flags & DNS_VERIFY_TRUSTED)) {
+			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+			error("@  WARNING: UNTRUSTED DNS RESOLUTION FOR HOST KEY!       @");
+			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+		}
+                if (flags & DNS_VERIFY_SECURE)
+                    validated_host_key_dns = 1;
+#endif
+
 		if (flags & DNS_VERIFY_FOUND) {
 
 			if (options.verify_host_key_dns == 1 &&
 			    flags & DNS_VERIFY_MATCH &&
 			    flags & DNS_VERIFY_SECURE)
+#ifndef DNSSEC_LOCAL_VALIDATION
 				return 0;
+#else
+                        {
+                            if (flags & DNS_VERIFY_MATCH)
+				matching_host_key_dns = 1;
+                            if (options.autoanswer_validated_keys)
+                                return check_host_key(host, hostaddr, options.port,
+                                                      host_key, RDRW,
+                                                      options.user_hostfiles, options.num_user_hostfiles,
+                                                      options.system_hostfiles, options.num_system_hostfiles);
+                            else
+				return 0;
+                        }
+#endif
 
 			if (flags & DNS_VERIFY_MATCH) {
 				matching_host_key_dns = 1;
@@ -1240,9 +1416,18 @@ warn_changed_key(Key *host_key)
 	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
 	error("@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @");
 	error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+#ifdef DNSSEC_LOCAL_VALIDATION
+        if (matching_host_key_dns && validated_host_key_dns) {
+            error("Howerver, a matching host key, validated by DNSSEC, was found.");
+        }
+        else {
+#endif
 	error("IT IS POSSIBLE THAT SOMEONE IS DOING SOMETHING NASTY!");
 	error("Someone could be eavesdropping on you right now (man-in-the-middle attack)!");
 	error("It is also possible that a host key has just been changed.");
+#ifdef DNSSEC_LOCAL_VALIDATION
+        }
+#endif
 	error("The fingerprint for the %s key sent by the remote host is\n%s.",
 	    key_type(host_key), fp);
 	error("Please contact your system administrator.");
