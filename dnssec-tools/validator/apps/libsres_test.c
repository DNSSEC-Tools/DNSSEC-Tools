/*
 * Portions Copyright (c) 1995, 1996, 1997 by Trusted Information Systems, Inc.
 *
 * Permission to use, copy modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND TRUSTED INFORMATION SYSTEMS
 * DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
 * TRUSTED INFORMATION SYSTEMS BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING
 * FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 * NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
 * WITH THE USE OR PERFORMANCE OF THE SOFTWARE.
 */
/*
 * Copyright 2005-2013 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */

#include "validator/validator-config.h"
#include <validator/validator.h>
#include <validator/resolver.h>

int
query_async_test(int async, int burst_max, int inflight_max, int numq)
{
#define NUMQ     4096
    struct expected_arrival *ea[NUMQ];
    char names[NUMQ][12];
    int   i, j, k, rc, in_flight = 0, nfds, ready, count = 0, burst, handled,
        sent = 0, answered = 0, unsent;
    struct name_server *ns;
    struct timeval     timeout, now;
    fd_set             activefds;

    ns = parse_name_server("192.168.1.7", NULL, 0);
    if (!ns) {
        printf("ns could not be created\n");
        free_name_servers(&ns);
        return -1;
    }

    memset(ea, 0x00, sizeof(ea));

    gettimeofday(&now, NULL);

    for (i=0; i < 26; ++i)
        for (j=0; j<26; ++j)
            for (k=0; k <26; ++k) {
                sprintf(names[count], "%c%c%c.com", 'a'+i, 'a'+j, 'a'+k);
                if (++count == numq) {
                    i=j=k=26;
                }
            }

  if (async) {
    FD_ZERO(&activefds);
    count = 0;
    do {
        // send as many as we can
        for( burst = 0;
             count < numq && burst < burst_max && in_flight < inflight_max;
             ++count, ++burst ) {
            ea[count] = res_async_query_send(names[count], ns_t_a, ns_c_in, ns);
            if (ea[count] == NULL) {
                printf("bad rc from res_async_query_send() @ count %d\n", count);
                break;
            }
            else {
                ++sent;
                ++in_flight;
                printf("sent %d %s (%d in flight)\n", count, names[count],
                       in_flight);
            }
        }
        unsent = numq - count;

        FD_ZERO(&activefds);
        nfds = 0;
        timeout.tv_sec = LONG_MAX;
        for (i = 0; i < numq; ++i) {
            if (!ea[i])
                continue;
            res_async_query_select_info(ea[i], &nfds, &activefds, &timeout);
        }
        /*
         * adjust libsres absoloute timeout to select relative timeout
         */
        if (timeout.tv_sec == LONG_MAX)
            timeout.tv_sec = 0;
        else {
            gettimeofday(&now, NULL);
            if (timeout.tv_sec > now.tv_sec)
                timeout.tv_sec -= now.tv_sec;
            else
                timeout.tv_sec = 0;
        }
        
        if (unsent && in_flight < inflight_max && timeout.tv_sec > 0) {
            printf("reducing timeout so we can send more\n");
            timeout.tv_sec = 0;
            timeout.tv_usec = 500;
        }
        printf("select @ %ld, %d fds, timeout %ld, %d in flight, %d unsent\n", 
               now.tv_sec, nfds, timeout.tv_sec, in_flight, unsent);
        if ((nfds <= 0) /*|| (timeout.tv_sec == 0)*/) {
            printf("no nfds but %d in flight??\n", in_flight);
            res_io_view();
            if ((timeout.tv_sec == 0) && (in_flight == inflight_max))
                break;
            continue;
        } else {
            printf("activefds: ");
            i = getdtablesize(); 
            if (i > FD_SETSIZE)
                i = FD_SETSIZE;
            for (--i; i >= 0; --i)
                if (FD_ISSET(i, &activefds)) {
                    printf("%d ", i);
                }
            printf("\n");
        }

        fflush(stdout);
        ready = select(nfds, &activefds, NULL, NULL, &timeout);
        gettimeofday(&now, NULL);
        printf("%d fds @ %ld\n", ready, now.tv_sec);
        if (ready < 0 && errno == EINTR)
            continue;

        if (ready == 0) {
            gettimeofday(&now, NULL);
            now.tv_usec = 0;
            printf("timeout @ %ld\n", now.tv_sec);

            /*
             * check for timeouts/retries
             */
            for (i = 0; i < numq; ++i) {
                if (!ea[i])
                    continue;
                rc = res_io_check_ea_list(ea[i], NULL, &now, NULL, NULL);
                in_flight += rc;
                if (rc < 0 && res_io_is_finished(ea[i])) {
                    res_async_query_free(ea[i]);
                    ea[i] = NULL;
                }
                printf("rc %d for %d (%d in flight)\n", rc, i, in_flight);
            }
            continue;
        }

        /*
         * check any ready tids
         */
        for (i = 0; ready && i < numq; ++i) {
            if (!ea[i])
                continue;
            handled = 0;
            rc = res_async_query_handle(ea[i], &handled, &activefds);
            if ((SR_UNSET == rc) || (SR_NO_ANSWER == rc)) {
                --in_flight;
                ready -= handled;
                printf("%sanswer for %d (%d in flight)\n",
                       (SR_NO_ANSWER == rc) ? "no " : "", i, in_flight);
                // dump_response(answer, answer_length);
                res_async_query_free(ea[i]);
                ea[i] = NULL;
                ++answered;
            }
        }
        
    } while (in_flight || count < numq);

  } else {
      struct name_server *server;
      u_char *response;
      size_t len;

    count = 0;
    // send as many as we can
    for( ; count < numq; ++count ) {
        rc = get(names[count], ns_t_a, ns_c_in, ns, &server, &response,
                 &len);
        ++sent;
        if ((rc >= 0) || (SR_NO_ANSWER == rc)) {
            ++answered;
            printf("sent %lu %s, got %lu bytes\n", 
                   (unsigned long)count, names[count], 
                   (unsigned long)len);
        }
        else {
            printf("bad rc %d/%lu bytes from get(%s) @ count %d\n", 
                   rc, (unsigned long)len,
                   names[count], count);
        }
    }
  }
    printf("sent %d, answered %d\n", sent, answered);
    free_name_servers(&ns);

    return 0;
}

int
main(int argc, char** argv)
{
    int async = atoi(argv[1]);
    int burst = atoi(argv[2]);
    int flight = atoi(argv[3]);
    int numq = atoi(argv[4]);

    res_set_debug_level(7);

    query_async_test(async, burst, flight, numq);

    return 0;
}
