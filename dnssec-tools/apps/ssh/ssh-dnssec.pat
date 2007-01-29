? fb6-build
? patch
? patch.1
? rsconfig
Index: configure.ac
===================================================================
RCS file: /cvs/openssh/configure.ac,v
retrieving revision 1.370
diff -u -p -r1.370 configure.ac
--- configure.ac	6 Oct 2006 23:07:21 -0000	1.370
+++ configure.ac	22 Dec 2006 12:35:02 -0000
@@ -3070,6 +3070,41 @@ AC_ARG_WITH(sectok,
 	]
 )
 
+LIBVAL_MSG="no"
+# Check whether user wants DNSSEC local validation support
+AC_ARG_WITH(local-dnssec-validation,
+	[  --with-local-dnssec-validation Enable local DNSSEC validation using libval],
+	[
+		if test "x$withval" != "xno" ; then
+			if test "x$withval" != "xyes" ; then
+				CPPFLAGS="$CPPFLAGS -I${withval}"
+				LDFLAGS="$LDFLAGS -L${withval}"
+				if test ! -z "$need_dash_r" ; then
+					LDFLAGS="$LDFLAGS -R${withval}"
+				fi
+				if test ! -z "$blibpath" ; then
+					blibpath="$blibpath:${withval}"
+				fi
+			fi
+			AC_CHECK_HEADERS(validator.h)
+			if test "$ac_cv_header_validator_h" != yes; then
+				AC_MSG_ERROR(Can't find validator.h)
+			fi
+			AC_CHECK_LIB(sres, query_send)
+			if test "$ac_cv_lib_sres_query_send" != yes; then
+				AC_MSG_ERROR(Can't find libsres)
+			fi
+			AC_CHECK_LIB(val, p_val_status)
+			if test "$ac_cv_lib_val_p_val_status" != yes; then
+				AC_MSG_ERROR(Can't find libval)
+			fi
+			AC_DEFINE(LOCAL_DNSSEC_VALIDATION, 1,
+				[Define if you want local DNSSEC validation support])
+			LIBVAL_MSG="yes"
+		fi
+	]
+)
+
 # Check whether user wants OpenSC support
 OPENSC_CONFIG="no"
 AC_ARG_WITH(opensc,
@@ -3972,6 +4007,7 @@ echo "              TCP Wrappers support
 echo "              MD5 password support: $MD5_MSG"
 echo "                   libedit support: $LIBEDIT_MSG"
 echo "  Solaris process contract support: $SPC_MSG"
+echo "   Local DNSSEC validation support: $LIBVAL_MSG"
 echo "       IP address in \$DISPLAY hack: $DISPLAY_HACK_MSG"
 echo "           Translate v4 in v6 hack: $IPV4_IN6_HACK_MSG"
 echo "                  BSD Auth support: $BSD_AUTH_MSG"
Index: dns.c
===================================================================
RCS file: /cvs/openssh/dns.c,v
retrieving revision 1.25
diff -u -p -r1.25 dns.c
--- dns.c	1 Sep 2006 05:38:36 -0000	1.25
+++ dns.c	22 Dec 2006 12:35:02 -0000
@@ -35,6 +35,10 @@
 #include <stdio.h>
 #include <string.h>
 
+#ifdef LOCAL_DNSSEC_VALIDATION
+# include <validator/validator.h>
+#endif
+
 #include "xmalloc.h"
 #include "key.h"
 #include "dns.h"
@@ -167,13 +171,19 @@ verify_host_key_dns(const char *hostname
 {
 	u_int counter;
 	int result;
-	struct rrsetinfo *fingerprints = NULL;
 
 	u_int8_t hostkey_algorithm;
 	u_int8_t hostkey_digest_type;
 	u_char *hostkey_digest;
 	u_int hostkey_digest_len;
 
+#ifndef LOCAL_DNSSEC_VALIDATION
+	struct rrsetinfo *fingerprints = NULL;
+#else
+	struct val_result_chain *val_rc, *val_results = NULL;
+	char hostname_n[NS_MAXDNAME];
+#endif
+
 	u_int8_t dnskey_algorithm;
 	u_int8_t dnskey_digest_type;
 	u_char *dnskey_digest;
@@ -190,6 +200,7 @@ verify_host_key_dns(const char *hostname
 		return -1;
 	}
 
+#ifndef LOCAL_DNSSEC_VALIDATION
 	result = getrrsetbyname(hostname, DNS_RDATACLASS_IN,
 	    DNS_RDATATYPE_SSHFP, 0, &fingerprints);
 	if (result) {
@@ -198,7 +209,7 @@ verify_host_key_dns(const char *hostname
 	}
 
 	if (fingerprints->rri_flags & RRSET_VALIDATED) {
-		*flags |= DNS_VERIFY_SECURE;
+		*flags |= (DNS_VERIFY_SECURE|DNS_VERIFY_TRUSTED);
 		debug("found %d secure fingerprints in DNS",
 		    fingerprints->rri_nrdatas);
 	} else {
@@ -246,6 +257,96 @@ verify_host_key_dns(const char *hostname
 
 	xfree(hostkey_digest); /* from key_fingerprint_raw() */
 	freerrset(fingerprints);
+#else
+	ns_name_pton(hostname, hostname_n, sizeof(hostname_n));
+	result = val_resolve_and_check(NULL, hostname_n, DNS_RDATACLASS_IN,
+	    DNS_RDATATYPE_SSHFP, VAL_QUERY_MERGE_RRSETS, &val_results);
+	if (result != VAL_NO_ERROR){
+		verbose("DNS lookup error: %s", p_ac_status(val_results->val_rc_status));
+		return -1;
+	}
+	//if ((result != VAL_NO_ERROR) ||
+	//    !val_istrusted(val_results->val_rc_status)) {
+	//	verbose("DNS lookup error: %s", p_ac_status(val_results->val_rc_status));
+		//return -1;
+	//}
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
+	for (val_rc = val_results; val_rc; val_rc = val_rc->val_rc_next)  {
+		struct val_authentication_chain *val_ac;
+		struct rr_rec *rr;
+
+		val_ac = val_rc->val_rc_answer;
+		if ((NULL == val_ac) || (NULL == val_ac->val_ac_rrset) ||
+		    (NULL == val_ac->val_ac_rrset->val_rrset_data))
+			continue;
+
+		for(rr = val_ac->val_ac_rrset->val_rrset_data; rr;
+		    rr = rr->rr_next) {
+
+			if (NULL == rr->rr_rdata)
+				continue;
+
+			++counter;
+			/*
+			 * Extract the key from the answer. Ignore any badly
+			 * formatted fingerprints.
+			 */
+			if (!dns_read_rdata(&dnskey_algorithm, &dnskey_digest_type,
+			    &dnskey_digest, &dnskey_digest_len,
+			    val_ac->val_ac_rrset->val_rrset_data->rr_rdata,
+			    val_ac->val_ac_rrset->val_rrset_data->rr_rdata_length_h)) {
+				verbose("Error parsing fingerprint from DNS.");
+				continue;
+			}
+
+			/* Check if the current key is the same as the given key */
+			if (hostkey_algorithm == dnskey_algorithm &&
+			    hostkey_digest_type == dnskey_digest_type) {
+
+				if (hostkey_digest_len == dnskey_digest_len &&
+				    memcmp(hostkey_digest, dnskey_digest,
+				    hostkey_digest_len) == 0) {
+
+					debug("found matching fingerprints in DNS");
+					*flags |= DNS_VERIFY_MATCH;
+				}
+			}
+			xfree(dnskey_digest);
+		}
+	}
+	if(counter)
+		*flags |= DNS_VERIFY_FOUND;
+	if (val_istrusted(val_results->val_rc_status)) {
+		/*
+		 * local validation can result in a non-secure, but trusted
+		 * response. For example, in a corporate network the authoritative
+		 * server for internal DNS may be on the internal network, behind
+		 * a firewall. Local validation policy can be configured to trust
+		 * these results without using DNSSEC to validate them.
+		 */
+		*flags |= DNS_VERIFY_TRUSTED;
+		if (val_isvalidated(val_results->val_rc_status)) {
+			*flags |= DNS_VERIFY_SECURE;
+			debug("found %d trusted fingerprints in DNS", counter);
+		} else  {
+			debug("found %d trusted, but not validated, fingerprints in DNS", counter);
+		}
+	} else {
+		debug("found %d un-trusted fingerprints in DNS", counter);
+	}
+
+	xfree(hostkey_digest); /* from key_fingerprint_raw() */
+	val_free_result_chain(val_results);
+#endif /* */
 
 	if (*flags & DNS_VERIFY_FOUND)
 		if (*flags & DNS_VERIFY_MATCH)
Index: dns.h
===================================================================
RCS file: /cvs/openssh/dns.h,v
retrieving revision 1.8
diff -u -p -r1.8 dns.h
--- dns.h	5 Aug 2006 02:39:40 -0000	1.8
+++ dns.h	22 Dec 2006 12:35:02 -0000
@@ -45,6 +45,7 @@ enum sshfp_hashes {
 #define DNS_VERIFY_FOUND	0x00000001
 #define DNS_VERIFY_MATCH	0x00000002
 #define DNS_VERIFY_SECURE	0x00000004
+#define DNS_VERIFY_TRUSTED	0x00000008
 
 int	verify_host_key_dns(const char *, struct sockaddr *, const Key *, int *);
 int	export_dns_rr(const char *, const Key *, FILE *, int);
Index: readconf.c
===================================================================
RCS file: /cvs/openssh/readconf.c,v
retrieving revision 1.136
diff -u -p -r1.136 readconf.c
--- readconf.c	1 Sep 2006 05:38:37 -0000	1.136
+++ readconf.c	22 Dec 2006 12:35:03 -0000
@@ -130,6 +130,7 @@ typedef enum {
 	oServerAliveInterval, oServerAliveCountMax, oIdentitiesOnly,
 	oSendEnv, oControlPath, oControlMaster, oHashKnownHosts,
 	oTunnel, oTunnelDevice, oLocalCommand, oPermitLocalCommand,
+	oStrictDnssecChecking,
 	oDeprecated, oUnsupported
 } OpCodes;
 
@@ -226,6 +227,11 @@ static struct {
 	{ "tunneldevice", oTunnelDevice },
 	{ "localcommand", oLocalCommand },
 	{ "permitlocalcommand", oPermitLocalCommand },
+#ifdef LOCAL_DNSSEC_VALIDATION
+	{ "strictdnssecchecking", oStrictDnssecChecking },
+#else
+	{ "strictdnssecchecking", oUnsupported },
+#endif
 	{ NULL, oBadOption }
 };
 
@@ -477,6 +483,10 @@ parse_yesnoask:
 			*intptr = value;
 		break;
 
+	case oStrictDnssecChecking:
+		intptr = &options->strict_dnssec_checking;
+                goto parse_yesnoask;
+
 	case oCompression:
 		intptr = &options->compression;
 		goto parse_flag;
@@ -1019,6 +1029,7 @@ initialize_options(Options * options)
 	options->batch_mode = -1;
 	options->check_host_ip = -1;
 	options->strict_host_key_checking = -1;
+	options->strict_dnssec_checking = -1;
 	options->compression = -1;
 	options->tcp_keep_alive = -1;
 	options->compression_level = -1;
@@ -1115,6 +1126,8 @@ fill_default_options(Options * options)
 		options->check_host_ip = 1;
 	if (options->strict_host_key_checking == -1)
 		options->strict_host_key_checking = 2;	/* 2 is default */
+	if (options->strict_dnssec_checking == -1)
+		options->strict_dnssec_checking = 2;	/* 2 is default */
 	if (options->compression == -1)
 		options->compression = 0;
 	if (options->tcp_keep_alive == -1)
Index: readconf.h
===================================================================
RCS file: /cvs/openssh/readconf.h,v
retrieving revision 1.63
diff -u -p -r1.63 readconf.h
--- readconf.h	5 Aug 2006 02:39:40 -0000	1.63
+++ readconf.h	22 Dec 2006 12:35:03 -0000
@@ -121,6 +121,8 @@ typedef struct {
 	char	*local_command;
 	int	permit_local_command;
 
+	int     strict_dnssec_checking;	/* Strict DNSSEC checking. */
+
 }       Options;
 
 #define SSHCTL_MASTER_NO	0
Index: sshconnect.c
===================================================================
RCS file: /cvs/openssh/sshconnect.c,v
retrieving revision 1.171
diff -u -p -r1.171 sshconnect.c
--- sshconnect.c	23 Oct 2006 17:02:24 -0000	1.171
+++ sshconnect.c	22 Dec 2006 12:35:04 -0000
@@ -26,6 +26,13 @@
 #include <netinet/in.h>
 #include <arpa/inet.h>
 
+#ifdef LOCAL_DNSSEC_VALIDATION
+# include <validator/validator.h>
+# define ADDRINFO_TYPE struct val_addrinfo
+#else
+#define ADDRINFO_TYPE struct addrinfo
+#endif
+
 #include <ctype.h>
 #include <errno.h>
 #include <netdb.h>
@@ -77,6 +84,31 @@ extern pid_t proxy_command_pid;
 static int show_other_keys(const char *, Key *);
 static void warn_changed_key(Key *);
 
+/* defaults to 'no' */
+static int
+confirm(const char *prompt)
+{
+	const char *msg, *again = "Please type 'yes' or 'no': ";
+	char *p;
+	int ret = -1;
+
+	if (options.batch_mode)
+		return 0;
+	for (msg = prompt;;msg = again) {
+		p = read_passphrase(msg, RP_ECHO);
+		if (p == NULL ||
+		    (p[0] == '\0') || (p[0] == '\n') ||
+		    strncasecmp(p, "no", 2) == 0)
+			ret = 0;
+		if (p && strncasecmp(p, "yes", 3) == 0)
+			ret = 1;
+		if (p)
+			xfree(p);
+		if (ret != -1)
+			return ret;
+	}
+}
+
 /*
  * Connect to the given ssh server using a proxy command.
  */
@@ -167,7 +199,7 @@ ssh_proxy_connect(const char *host, u_sh
  * Creates a (possibly privileged) socket for use as the ssh connection.
  */
 static int
-ssh_create_socket(int privileged, struct addrinfo *ai)
+ssh_create_socket(int privileged, ADDRINFO_TYPE *ai)
 {
 	int sock, gaierr;
 	struct addrinfo hints, *res;
@@ -305,7 +337,8 @@ ssh_connect(const char *host, struct soc
 	int on = 1;
 	int sock = -1, attempt;
 	char ntop[NI_MAXHOST], strport[NI_MAXSERV];
-	struct addrinfo hints, *ai, *aitop;
+	struct addrinfo hints;
+	ADDRINFO_TYPE *ai, *aitop = NULL;
 
 	debug2("ssh_connect: needpriv %d", needpriv);
 
@@ -319,9 +352,44 @@ ssh_connect(const char *host, struct soc
 	hints.ai_family = family;
 	hints.ai_socktype = SOCK_STREAM;
 	snprintf(strport, sizeof strport, "%u", port);
+#ifndef LOCAL_DNSSEC_VALIDATION
 	if ((gaierr = getaddrinfo(host, strport, &hints, &aitop)) != 0)
-		fatal("%s: %.100s: %s", __progname, host,
-		    gai_strerror(gaierr));
+		fatal("%s: %.100s: %s", __progname, host, gai_strerror(gaierr));
+#else
+	if ((gaierr = val_getaddrinfo(NULL, host, strport, &hints, &aitop)) != 0)
+		fatal("%s: %.100s: %s", __progname, host, gai_strerror(gaierr));
+	debug("ValStatus: %s", p_val_status(aitop->ai_val_status));
+	if (!val_istrusted(aitop->ai_val_status)) {
+		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+		error("@ WARNING: UNTRUSTED DNS RESOLOUTION FOR HOST IP ADRRESS! @");
+		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+		error("The authenticity of DNS data for the host '%.200s' "
+		    "can't be established.", host);
+		if (options.strict_dnssec_checking == 1) {
+			fatal("DNS resolution is not trusted (%s) "
+			    "and you have requested strict checking",
+			    p_val_status(aitop->ai_val_status));
+		} else if (options.strict_dnssec_checking == 2) {
+			char msg[1024];
+			for (ai = aitop; ai; ai = ai->ai_next) {
+				if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6)
+					continue;
+				if (getnameinfo(ai->ai_addr, ai->ai_addrlen,
+				    ntop, sizeof(ntop), strport, sizeof(strport),
+				    NI_NUMERICHOST|NI_NUMERICSERV) != 0) {
+					error("ssh_connect: getnameinfo failed");
+					continue;
+				}
+				error(" IP address %s port %s", ntop, strport);
+			}
+			snprintf(msg,sizeof(msg),
+			    "Are you sure you want to attempt to connect "
+			    "(yes/no)? ");
+			if (!confirm(msg))
+				return (-1);
+		}
+	}
+#endif /* LOCAL_DNSSEC_VALIDATION */
 
 	for (attempt = 0; attempt < connection_attempts; attempt++) {
 		if (attempt > 0) {
@@ -366,8 +434,12 @@ ssh_connect(const char *host, struct soc
 		if (sock != -1)
 			break;	/* Successful connection. */
 	}
-
+        
+#ifndef LOCAL_DNSSEC_VALIDATION
 	freeaddrinfo(aitop);
+#else
+	val_freeaddrinfo(aitop);
+#endif /* LOCAL_DNSSEC_VALIDATION */
 
 	/* Return failure if we didn't get a successful connection. */
 	if (sock == -1) {
@@ -496,31 +568,6 @@ ssh_exchange_identification(void)
 	debug("Local version string %.100s", client_version_string);
 }
 
-/* defaults to 'no' */
-static int
-confirm(const char *prompt)
-{
-	const char *msg, *again = "Please type 'yes' or 'no': ";
-	char *p;
-	int ret = -1;
-
-	if (options.batch_mode)
-		return 0;
-	for (msg = prompt;;msg = again) {
-		p = read_passphrase(msg, RP_ECHO);
-		if (p == NULL ||
-		    (p[0] == '\0') || (p[0] == '\n') ||
-		    strncasecmp(p, "no", 2) == 0)
-			ret = 0;
-		if (p && strncasecmp(p, "yes", 3) == 0)
-			ret = 1;
-		if (p)
-			xfree(p);
-		if (ret != -1)
-			return ret;
-	}
-}
-
 /*
  * check whether the supplied host key is valid, return -1 if the key
  * is not valid. the user_hostfile will not be updated if 'readonly' is true.
@@ -905,6 +952,20 @@ verify_host_key(char *host, struct socka
 	if (options.verify_host_key_dns &&
 	    verify_host_key_dns(host, hostaddr, host_key, &flags) == 0) {
 
+#ifdef LOCAL_DNSSEC_VALIDATION
+		/*
+		 * local validation can result in a non-secure, but trusted
+		 * response. For example, in a corporate network the authoritative
+		 * server for internal DNS may be on the internal network, behind
+		 * a firewall. Local validation policy can be configured to trust
+		 * these results without using DNSSEC to validate them.
+		 */
+		if (!(flags & DNS_VERIFY_TRUSTED)) {
+			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+			error("@  WARNING: UNTRUSTED DNS RESOLOUTION FOR HOST KEY!       @");
+			error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
+		}
+#endif
 		if (flags & DNS_VERIFY_FOUND) {
 
 			if (options.verify_host_key_dns == 1 &&
