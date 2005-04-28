
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
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 

#ifndef RES_ERRORS_H
#define RES_ERRORS_H

#define NO_DATA_IN_ANSWER	XX // no data for type 
#define LAME_DELEGATION	XX
#define ANSWER_REFUSED	XX // Generic header error
#define NO_GLUE	XX
#define GLUE_MISMATCH	XX
#define DUPLICATE_RR	XX

#define SR_UNSET	0
#define SR_NULLPTR_ERROR	2
#define SR_CALL_ERROR	3
#define SR_INITIALIZATION_ERROR      4
#define SR_HEADER_ERROR	5
#define SR_TSIG_ERROR	6
#define SR_MEMORY_ERROR		7
#define SR_INTERNAL_ERROR	8	
#define SR_MESSAGE_ERROR         9
#define SR_DATA_MISSING_ERROR       10
#define SR_REFERRAL_ERROR       11
#define SR_NO_ANSWER	12
#define SR_EMPTY_NXDOMAIN       60
/* Unstable states (i.e., used internally only) */
#define SR_DATA_UNCHECKED       66
#define SR_PROCESS_ERROR	-9


#endif /* RES_ERRORS_H */
