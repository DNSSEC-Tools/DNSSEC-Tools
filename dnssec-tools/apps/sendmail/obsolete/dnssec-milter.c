/*
 *
 * Copyright 2004 Sparta, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 *
 * This mail filter checks if the domain-name to IP-address mapping
 * of the sending mail server and the sending domain's SPF record is
 * dnssec validated or not.
 *
 * Author: Abhijit Hayatnagarkar
 *         Sparta, Inc.
 */

#include <stdio.h>
#include <sysexits.h>
#include <string.h>
#include <stdlib.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <spf.h>

#include "libmilter/mfapi.h"
#include "validator.h"

#ifndef bool
#define bool	int
#define TRUE	1
#define FALSE	0
#endif /* ! bool */

#define BUFSIZE 1024

char *logfile = NULL;
bool reject_flag = FALSE;

/*
 * From RFC 821
 */
char RCODE_NO_ACCESS[] = "550";

/*
 * From RFC 1893
 * 5.X.X   Permanent Failure
 * X.7.1   Delivery not authorized, message refused
 */
char XCODE_MESSAGE_REFUSED[] = "5.7.1";

struct dnssecPriv
{
    char *dnssec_connectfrom;
    bool dnssec_validated;
    FILE *logfp;
};

void dnssec_log(FILE *logfp, const char *message) {
    if (logfp != NULL) {
	fprintf(logfp, message);
    }
}

sfsistat dnssec_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr)
{
    char logmsg[BUFSIZE];
    struct dnssecPriv *priv;
    bool status = FALSE;
    FILE *logfp = NULL;
    
    bzero(logmsg, BUFSIZE);
    
    if ((logfile == NULL) || ((logfp = fopen(logfile, "a+")) == NULL)) {
	fprintf(stderr, "dnssec-milter: error opening logfile\n");
    }
    
    if (hostname == NULL) {
	snprintf(logmsg, BUFSIZE,
		 "dnssec-milter: could not determine sender's domain name.\n");
	dnssec_log(logfp, logmsg);
	return SMFIS_REJECT;
    }
    
    if (dnssec_validate(hostname)) {
	snprintf(logmsg, BUFSIZE,
		 "dnssec-milter: sender's domain name %s successfully validated.\n",
		 hostname);
	dnssec_log(logfp, logmsg);
	status = TRUE;
    }
    else {
	snprintf(logmsg, BUFSIZE,
		 "dnssec-milter: could not validate sender's domain name %s\n",
		 hostname);
	dnssec_log(logfp, logmsg);
	status = FALSE;
    }
    
    /* allocate some private memory */
    priv = malloc (sizeof *priv);
    if (priv == NULL) {
	/* can't accept this message right now */
	return SMFIS_TEMPFAIL;
    }
    memset (priv, '\0', sizeof *priv);
    
    /* save the private data */
    smfi_setpriv(ctx, priv);
    priv->dnssec_validated = status;
    priv->logfp = logfp;
    if ((priv->dnssec_connectfrom = strdup(hostname)) == NULL) {
	return SMFIS_TEMPFAIL;
    }
    
    if ((reject_flag == TRUE) && (priv->dnssec_validated == FALSE)){
	/* if the reject flag was set, reject this message */
	snprintf(logmsg, BUFSIZE,
		 "dnssec-milter: rejecting mail from %s\n", hostname);
	dnssec_log(logfp, logmsg);

    }

    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_helo(SMFICTX *ctx, char *helohost)
{
    char replymsg[BUFSIZE];
    struct dnssecPriv *priv = (struct dnssecPriv *) smfi_getpriv(ctx);

    bzero(replymsg, BUFSIZE);

    if ((reject_flag == TRUE) && (priv->dnssec_validated == FALSE)){
	snprintf(replymsg, BUFSIZE,
		 "The dnssec-validation of %s failed\n", priv->dnssec_connectfrom);
	smfi_setreply(ctx, RCODE_NO_ACCESS, XCODE_MESSAGE_REFUSED,
		      replymsg);
	return SMFIS_REJECT;
    }

    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_envfrom(SMFICTX *ctx, char **argv)
{
    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_envrcpt(SMFICTX *ctx, char **argv)
{
    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_header(SMFICTX *ctx, char *headerf, char *headerv)
{
    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_eoh(SMFICTX *ctx)
{
    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen)
{
    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_eom(SMFICTX *ctx)
{
    char msgbuf[BUFSIZE];
    bzero(msgbuf, BUFSIZE);
    
    struct dnssecPriv *priv = (struct dnssecPriv *) smfi_getpriv(ctx);
    
    /* add a header to the message to indicate dnssec processing */
    if (priv->dnssec_connectfrom != NULL) {
	if (priv->dnssec_validated) {
	    snprintf (msgbuf, BUFSIZE,
		      "pass (The dnssec-validation of the domain %s was successful.)",
		      priv->dnssec_connectfrom);
	}
	else {
	    snprintf (msgbuf, BUFSIZE,
		      "fail (The dnssec-validation of the domain %s failed.)",
		      priv->dnssec_connectfrom);
	}
	if (smfi_addheader(ctx, "DNSSec-Validation", msgbuf) != MI_SUCCESS) {
	    fprintf(stderr, "Couldn't add header: DNSSec-Validation: %s\n",
		    msgbuf);
	}
    }
    
    /* continue processing */
    return SMFIS_CONTINUE;
}

sfsistat dnssec_abort(SMFICTX *ctx)
{
    return SMFIS_CONTINUE;
}

sfsistat dnssec_close(SMFICTX *ctx)
{
    /* release private memory */
    struct dnssecPriv *priv = (struct dnssecPriv *) smfi_getpriv(ctx);
    if (priv == NULL) {
	return;
    }
    
    if (priv->dnssec_connectfrom != NULL) {
	free (priv->dnssec_connectfrom);
    }
    
    if (priv != NULL) {
	free(priv);
    }
    smfi_setpriv(ctx, NULL);
    
    /* close logfile pointer */
    fclose(priv->logfp);
    return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
    {
	"dnssec-milter",/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS | SMFIF_CHGBODY,
	/* flags */
	dnssec_connect,	/* connection info filter */
	dnssec_helo,	/* SMTP HELO command filter */
	dnssec_envfrom,	/* envelope sender filter */
	dnssec_envrcpt,	/* envelope recipient filter */
	dnssec_header,	/* header filter */
	dnssec_eoh,	/* end of header */
	dnssec_body,	/* body block filter */
	dnssec_eom,	/* end of message */
	dnssec_abort,	/* message aborted */
	dnssec_close,	/* connection cleanup */
    };

static void
usage(prog)
     char *prog;
{
    fprintf(stderr,
	    "Usage: %s %s\n\t%s\n\t%s\n\t%s\n\t%s\n\t%s\n",
	    prog,
	    "-p socket-addr [-t timeout] [-l log-file] [-r]",
	    "-p\tthe port/socket on which milter will talk to us",
	    "-t\ttimeout for this filter",
	    "-l\tthe log file in which to log events for this filter",
	    "-r\treject messages if dnssec-validation fails",
	    "\t(the default is to add a header to the message)");
}

int
main(argc, argv)
     int argc;
     char **argv;
{
    bool setconn = FALSE;
    int c, retval;
    const char *args = "p:t:l:rh";
    extern char *optarg;
    FILE *logfp = NULL;
    
    reject_flag = FALSE;
    
    /* Process command line options */
    while ((c = getopt(argc, argv, args)) != -1)
	{
	    switch (c)
		{
		case 'p':
		    if (optarg == NULL || *optarg == '\0')
			{
			    (void) fprintf(stderr, "Illegal conn: %s\n",
					   optarg);
			    exit(EX_USAGE);
			}
		    if (smfi_setconn(optarg) == MI_FAILURE)
			{
			    (void) fprintf(stderr,
					   "smfi_setconn failed\n");
			    exit(EX_SOFTWARE);
			}
		    
		    /*
		    **  If we're using a local socket, make sure it
		    **  doesn't already exist.  Don't ever run this
		    **  code as root!!
		    */
		    
		    if (strncasecmp(optarg, "unix:", 5) == 0)
			unlink(optarg + 5);
		    else if (strncasecmp(optarg, "local:", 6) == 0)
			unlink(optarg + 6);
		    setconn = TRUE;
		    break;
		    
		case 't':
		    if (optarg == NULL || *optarg == '\0')
			{
			    (void) fprintf(stderr, "Illegal timeout: %s\n",
					   optarg);
			    exit(EX_USAGE);
			}
		    if (smfi_settimeout(atoi(optarg)) == MI_FAILURE)
			{
			    (void) fprintf(stderr,
					   "smfi_settimeout failed\n");
			    exit(EX_SOFTWARE);
			}
		    break;
		    
		case 'l':
		    if (optarg == NULL || *optarg == '\0')
		        {
			    (void) fprintf(stderr, "Illegal filename: %s\n",
					   optarg);
			    exit(EX_USAGE);
			}
		    if ((logfp = fopen(optarg, "a+")) == NULL) {
			(void) fprintf(stderr, "Error opening file: %s\n",
				       optarg);
			exit(EX_USAGE);
		    }
		    fclose(logfp);
		    logfile = optarg;
		    break;
		    
		case 'r':
		    reject_flag = TRUE;
		    break;
		    
		case 'h':
		default:
		    usage(argv[0]);
		    exit(EX_USAGE);
		}
	}
    if (!setconn)
	{
	    fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
	    usage(argv[0]);
	    exit(EX_USAGE);
	}
    if (smfi_register(smfilter) == MI_FAILURE)
	{
	    fprintf(stderr, "smfi_register failed\n");
	    exit(EX_UNAVAILABLE);
	}
    retval = smfi_main();
    
    return retval;
}
