/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * A command-line tool for testing the val_get_dane() function.
 */
#include "validator/validator-config.h"
#include <validator/validator.h>
#include <validator/val_dane.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#define	NAME	"dane_check"
#define	VERS	"version: 1.0"
#define	DTVERS	"DNSSEC-Tools version: 1.8"

#ifdef HAVE_GETOPT_LONG
static struct option prog_options[] = {
    {"help", 0, 0, 'h'},
    {"label", 1, 0, 'l'},
    {"proto", 1, 0, 'x'},
    {"port", 1, 0, 'p'},
    {"output", 1, 0, 'o'},
    {"sync", 0, 0, 's'},
    {"dnsval-conf", 1, 0, 'v'},
    {"root-hints", 1, 0, 'i'},
    {"resolv-conf", 1, 0, 'r'},
    {"Version", 0, 0, 'V'},
    {0, 0, 0, 0}
};
#endif

void
usage(char *progname)
{
    fprintf(stderr,
            "Usage: %s [options] <hostname>\n",
            progname);
    fprintf(stderr, "Options:\n");
    fprintf(stderr,
            "\t-h, --help                      display usage and exit\n");
    fprintf(stderr, 
            "\t-l, --label=<label-string>      validation policy label\n");
    fprintf(stderr,
            "\t-x, --proto=<tcp|udp|sctp>      TLSA protocol\n");
    fprintf(stderr,
            "\t-p, --port=<port number>        TLSA port\n");
    fprintf(stderr,
            "\t-o, --output=<debug-level>:<dest-type>[:<dest-options>]\n"
            "\t          <debug-level> is 1-7, corresponding to syslog levels\n"
            "\t          <dest-type> is one of file, net, syslog, stderr, stdout\n"
            "\t          <dest-options> depends on <dest-type>\n"
            "\t              file:<file-name>   (opened in append mode)\n" 
            "\t              net[:<host-name>:<host-port>] (127.0.0.1:1053\n" 
            "\t              syslog[:facility] (0-23 (default 1 USER))\n" );
    fprintf(stderr,
            "\t-s, --sync                      perform synchronous lookup\n");
    fprintf(stderr,
            "\t-v, --dnsval-conf=<file> Specifies a dnsval.conf\n");
    fprintf(stderr,
            "\t-r, --resolv-conf=<file> Specifies a resolv.conf to search\n"
            "\t                         for nameservers\n");
    fprintf(stderr,
            "\t-i, --root-hints=<file> Specifies a root.hints to search\n" 
            "\t                        for root nameservers\n");
    fprintf(stderr,
            "\t-V, --Version                   display version and exit\n");

}

void
version(void)
{
     fprintf(stderr, "%s %s\n", NAME, VERS);
     fprintf(stderr, "%s\n", DTVERS);
}



#ifndef VAL_NO_ASYNC
struct dane_cb {
    int *retval;
    struct val_danestatus **danestatus;
    int done;
};

struct getaddr_s {
    int *retval;
    struct addrinfo **ainfo;
    val_status_t     *vstatus;
    int               done;
};

static int 
_danecallback(void *callback_data, 
          int dane_rc, 
          struct val_danestatus **res)
{
    struct dane_cb *dcb = (struct dane_cb *)callback_data;

    *dcb->retval = dane_rc;
    if (res != NULL) {
        *dcb->danestatus = *res;
        *res = NULL;
    }
    else
        *dcb->danestatus = NULL;
    dcb->done = 1;

    val_log(NULL, LOG_DEBUG, "_danecallback %p %d %p\n", 
            callback_data, dane_rc, res);

    return 0; /* OK */
}

static int
_aicallback(void *callback_data, int eai_retval, struct addrinfo *res,
          val_status_t val_status)
{
    struct getaddr_s *gas = (struct getaddr_s*)callback_data;

    *gas->retval = eai_retval;
    *gas->ainfo = res;
    *gas->vstatus = val_status;
    gas->done = 1;

    val_log(NULL, LOG_DEBUG, "_aicallback %p %d %p %d\n", 
            callback_data, eai_retval, res, val_status);

    return 0; /* OK */
}


#endif

static const char *
ssl_error(void)
{
    /* Minimum requirement is 120 characters */
    static char ssl_errbuf[256];
    ERR_error_string_n(ERR_get_error(), ssl_errbuf, sizeof(ssl_errbuf));
    return ssl_errbuf;
}


int
main(int argc, char *argv[])
{
    const char     *allowed_args = "hl:x:p:o:sv:i:r:V";
    char           *node = NULL;
    int             retval;
    int             async = 1;
    val_log_t      *logp;
    char           *label_str = NULL;
    struct val_daneparams daneparams;
    struct val_danestatus *danestatus = NULL;
    int port = 443;
    int proto = DANE_PARAM_PROTO_TCP;
    val_context_t *context = NULL;
    val_status_t val_status;
    struct addrinfo *val_ainfo = NULL;
    struct addrinfo hints;
    int ret = 0;
    int dane_retval = VAL_DANE_INTERNAL_ERROR;
    int ai_retval = 0;

    /* Parse the command line */
    while (1) {
        int             c;
#ifdef HAVE_GETOPT_LONG
        int             opt_index = 0;
#ifdef HAVE_GETOPT_LONG_ONLY
        c = getopt_long_only(argc, argv, allowed_args,
                             prog_options, &opt_index);
#else
        c = getopt_long(argc, argv, allowed_args, prog_options, &opt_index);
#endif
#else                           /* only have getopt */
        c = getopt(argc, argv, allowed_args);
#endif

        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage(argv[0]);
            return -1;
        case 'l':
            label_str = optarg;
            break;
        case 'o':
            logp = val_log_add_optarg(optarg, 1);
            if (NULL == logp) { /* err msg already logged */
                usage(argv[0]);
                return -1;
            }
            break;

        case 's':
            async = 0;
            break;

        case 'p':
            port = atoi(optarg);
            break;

        case 'x':
            if(strncmp(optarg, DANE_PARAM_PROTO_STR_TCP,
                       strlen(DANE_PARAM_PROTO_STR_TCP)))
                proto = DANE_PARAM_PROTO_TCP;
            else if (strncmp(optarg, DANE_PARAM_PROTO_STR_UDP,
                        strlen(DANE_PARAM_PROTO_STR_UDP)))
                proto = DANE_PARAM_PROTO_UDP;
            else if (strncmp(optarg, DANE_PARAM_PROTO_STR_SCTP, 
                        strlen(DANE_PARAM_PROTO_STR_SCTP)))
                proto = DANE_PARAM_PROTO_SCTP;
            else {
                usage(argv[0]);
                return -1;
            }
            break;

        case 'v':
            dnsval_conf_set(optarg);
            break;

        case 'i':
            root_hints_set(optarg);
            break;

        case 'r':
            resolv_conf_set(optarg);
            break;

        case 'V':
            version();
            return 0;
        default:
            fprintf(stderr, "Invalid option %s\n", argv[optind - 1]);
            usage(argv[0]);
            return -1;
        }
    }

    if (optind < argc) {
        node = argv[optind++];
    } else {
        fprintf(stderr, "Error: node name not specified\n");
        usage(argv[0]);
        return -1;
    }

    if (VAL_NO_ERROR != (retval = 
                val_create_context(label_str, &context))) {
        fprintf(stderr, "Cannot create context %s(%d)\n", 
                p_val_error(retval), retval);
        return -1;
    }

    daneparams.port = port;
    daneparams.proto = proto;
    memset(&hints, 0, sizeof(struct addrinfo));
#ifdef AI_ADDRCONFIG
    hints.ai_flags = AI_ADDRCONFIG;
#endif

    if (!async) {
        /* synchronous lookup and validation */
        ai_retval = val_getaddrinfo(context, node, NULL, &hints,
                                    &val_ainfo, &val_status);
        dane_retval = val_getdaneinfo(context, node, &daneparams, &danestatus); 
    }
    else {
#ifdef VAL_NO_ASYNC
        fprintf(stderr, "async support not available\n");
#else
        struct dane_cb cb_data_dane = { &dane_retval, &danestatus, 0 };
        val_dane_callback my_dane_cb = &_danecallback;
        struct timeval tv;
        val_async_status *das = NULL; /* helps us cancel the lookup if we need to */

        struct getaddr_s cb_data_ai = { &ai_retval, &val_ainfo, &val_status, 0 };
        val_gai_callback my_ai_cb = &_aicallback;
        val_gai_status *status = NULL;

        /*
         * submit requests
         */
        if (VAL_NO_ERROR != val_dane_submit(context, node, &daneparams,
                                 my_dane_cb, &cb_data_dane, &das) ||
            VAL_NO_ERROR != val_getaddrinfo_submit(context, node, NULL,
                                &hints, my_ai_cb, &cb_data_ai, 0, &status)) {
            dane_retval = VAL_DANE_INTERNAL_ERROR; 
            goto done;
        }

        /*
         * wait for it to complete
         */
#if 0
        while(0 == cb_data_dane.done ||
              0 == cb_data_ai.done) {
            tv.tv_sec = 10;
            tv.tv_usec = 0;
            val_async_check_wait(context, NULL, NULL, &tv, 0);
        }
#endif

#if 1
        while(0 == cb_data_dane.done || 
              0 == cb_data_ai.done) {
            fd_set  activefds;
            int nfds = 0;
            int ready;

            FD_ZERO(&activefds);

            tv.tv_sec = 10; /* 10 sec */
            tv.tv_usec = 0;

            val_async_select_info(context, &activefds, &nfds, &tv);
            ready = select(nfds+1, &activefds, NULL, NULL, &tv);
            if (ready < 0) {
                continue;
            } 
            val_async_check(context, &activefds, &nfds, 0);
        }
#endif

#endif
    }

done:
    if (ai_retval != 0) {
        fprintf(stderr, "Error in val_getaddrinfo(): %d\n", ai_retval);
        return -1;
    }

    if (!val_istrusted(val_status)) {
        fprintf(stderr, 
                "Address lookup information could not be validated: %s\n", 
                p_val_status(val_status));

    } else if(dane_retval == VAL_DANE_NOERROR && 
              proto == DANE_PARAM_PROTO_TCP) {

        /* Set up the SSL connection */
        SSL_library_init();
        SSL_load_error_strings();
        const SSL_METHOD *meth = SSLv23_client_method();
        SSL_CTX *ctx = SSL_CTX_new(meth);
        struct addrinfo *ai = NULL;
        int presetup_okay;

        /*
         * OpenSSL only does protocol negotiation on SSLv23_client_method;
         * we need to set SNI to get the correct certificate from many
         * modern browsers, so we disable both SSLv2 and SSLv3 if we can.
         * That leaves (currently) TLSv1.0 TLSv1.1 TLSv1.2
         */
        long ssl_options = 0
#ifdef SSL_OP_NO_SSLv2
            | SSL_OP_NO_SSLv2
#endif
#ifdef SSL_OP_NO_SSLv3
            | SSL_OP_NO_SSLv3
#endif
            ;

        if (!SSL_CTX_set_options(ctx, ssl_options)) {
            fprintf(stderr, "Failed to set SSL context options (%ld): %s\n",
              ssl_options, ssl_error());
            presetup_okay = 0;
        } else {
            presetup_okay = 1;
        }


        ai = val_ainfo;
        while(presetup_okay && ai && (ai->ai_protocol == IPPROTO_TCP) && 
             (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)) {

            int do_pathval = 0;
            int sock;
            char buf[INET6_ADDRSTRLEN];
            size_t buflen = sizeof(buf);
            const char *addr = NULL;

            if (ai->ai_family == AF_INET) {
                sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                ((struct sockaddr_in *)(ai)->ai_addr)->sin_port = htons(port);
            } else {
                sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
                ((struct sockaddr_in6 *)(ai)->ai_addr)->sin6_port = htons(port);
            }

            INET_NTOP(ai->ai_family, ai->ai_addr, sizeof(ai->ai_addr), buf, buflen, addr);
            fprintf(stderr, "Connecting to %s\n", addr);

            if (0 == connect(sock, ai->ai_addr, ai->ai_addrlen)) {
                int err;
                SSL *ssl = SSL_new(ctx);
                BIO * sbio = BIO_new_socket(sock,BIO_NOCLOSE);

#if OPENSSL_VERSION_NUMBER >= 0x0090806fL && !defined(OPENSSL_NO_TLSEXT)
                SSL_set_tlsext_host_name(ssl, node);
#endif

                SSL_set_bio(ssl,sbio,sbio);
                if((err = SSL_connect(ssl)) == 1) {
                    dane_retval = val_dane_check(context,
                                                 ssl,
                                                 danestatus,
                                                 &do_pathval);
                    fprintf(stderr,
                            "DANE validation for %s returned %s(%d)\n", 
                            node,
                            p_dane_error(dane_retval), dane_retval);
                } else {
                    fprintf(stderr, "SSL Connect to %s failed: %d\n", node, err);
                }
                SSL_shutdown(ssl);
                SSL_free(ssl);
            } else {
                fprintf(stderr, "TCP Connect to %s failed\n", node);
            }

            if (dane_retval != VAL_DANE_NOERROR)
                ret = -1;

            ai = (struct addrinfo *) (ai->ai_next);
        }

    } else if (dane_retval == VAL_DANE_IGNORE_TLSA) {
        fprintf(stderr, "TLSA is provably non-existent.\n");
    } else {
        fprintf(stderr, "TLSA record could not be validated.\n");
    }

    if (danestatus != NULL)
        val_free_dane(danestatus);

    if (val_ainfo != NULL)
        val_freeaddrinfo(val_ainfo);    

    if (context)
        val_free_context(context);

    val_free_validator_state();

    return ret;
}
