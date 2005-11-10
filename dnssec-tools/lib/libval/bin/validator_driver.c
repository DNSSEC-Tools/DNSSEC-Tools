/*
 * Copyright 2005 SPARTA, Inc.  All rights reserved.
 * See the COPYING file distributed with this software for details.
 */ 

#include <stdio.h>
#include <arpa/nameser.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <resolver.h>
#include <validator.h>

struct testcase_st {
	const char *desc;
	const char *qn;
	const u_int16_t qc;	
	const u_int16_t qt;	
	const int qr;
};

static const struct testcase_st testcases[] = {
#if 1
	{"Test Case 1", "good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 2", "badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 3", "nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 4", "baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 5", "futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 6", "pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 7", "good-cname-to-good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 8", "good-cname-to-badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 9", "good-cname-to-nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 10", "good-cname-to-baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 11", "good-cname-to-futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 12", "good-cname-to-pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 13", "badsign-cname-to-good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 14", "badsign-cname-to-badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 15", "badsign-cname-to-nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 16", "badsign-cname-to-baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 17", "badsign-cname-to-futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 18", "badsign-cname-to-pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 19", "nosig-cname-to-good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 20", "nosig-cname-to-badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 21", "nosig-cname-to-nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 22", "nosig-cname-to-baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 23", "nosig-cname-to-futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 24", "nosig-cname-to-pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 25", "baddata-cname-to-good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 26", "baddata-cname-to-badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 27", "baddata-cname-to-nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 28", "baddata-cname-to-baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 29", "baddata-cname-to-futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 30", "baddata-cname-to-pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 31", "futuredate-cname-to-good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 32", "futuredate-cname-to-badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 33", "futuredate-cname-to-nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 34", "futuredate-cname-to-baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 35", "futuredate-cname-to-futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 36", "futuredate-cname-to-pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 37", "pastdate-cname-to-good-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 38", "pastdate-cname-to-badsign-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 39", "pastdate-cname-to-nosig-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 40", "pastdate-cname-to-baddata-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 41", "pastdate-cname-to-futuredate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 42", "pastdate-cname-to-pastdate-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 43", "good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 44", "badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 45", "nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 46", "baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 47", "futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 48", "pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 49", "good-cname-to-good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 50", "good-cname-to-badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 51", "good-cname-to-nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 52", "good-cname-to-baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 53", "good-cname-to-futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 54", "good-cname-to-pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 55", "badsign-cname-to-good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 56", "badsign-cname-to-badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 57", "badsign-cname-to-nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 58", "badsign-cname-to-baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 59", "badsign-cname-to-futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 60", "badsign-cname-to-pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 61", "nosig-cname-to-good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 62", "nosig-cname-to-badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 63", "nosig-cname-to-nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 64", "nosig-cname-to-baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 65", "nosig-cname-to-futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 66", "nosig-cname-to-pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 67", "baddata-cname-to-good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 68", "baddata-cname-to-badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 69", "baddata-cname-to-nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 70", "baddata-cname-to-baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 71", "baddata-cname-to-futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 72", "baddata-cname-to-pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 73", "futuredate-cname-to-good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 74", "futuredate-cname-to-badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 75", "futuredate-cname-to-nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 76", "futuredate-cname-to-baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 77", "futuredate-cname-to-futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 78", "futuredate-cname-to-pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 79", "pastdate-cname-to-good-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 80", "pastdate-cname-to-badsign-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 81", "pastdate-cname-to-nosig-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 82", "pastdate-cname-to-baddata-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 83", "pastdate-cname-to-futuredate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 84", "pastdate-cname-to-pastdate-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 85", "good-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 86", "badsign-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 87", "nosig-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 88", "baddata-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 89", "futuredate-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 90", "pastdate-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATE_SUCCESS},
	{"Test Case 91", "good-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 92", "badsign-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 93", "nosig-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 94", "baddata-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 95", "futuredate-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 96", "pastdate-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATE_SUCCESS},
	{"Test Case 97", "addedlater-A.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	NONEXISTENT_NAME},
	{"Test Case 98", "addedlater-AAAA.good-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	NONEXISTENT_NAME},
	{"Test Case 99", "good-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 100", "badsign-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 101", "nosig-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 102", "baddata-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 103", "futuredate-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 104", "pastdate-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROVABLE},
	{"Test Case 105", "good-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 106", "badsign-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 107", "nosig-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 108", "baddata-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 109", "futuredate-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 110", "pastdate-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROVABLE},
	{"Test Case 111", "addedlater-A.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROOF},
	{"Test Case 112", "addedlater-AAAA.badsign-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROOF},
	{"Test Case 113", "good-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 114", "badsign-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 115", "nosig-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 116", "baddata-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 117", "futuredate-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	DNS_ERROR_BASE+SR_NO_ANSWER},
	{"Test Case 118", "pastdate-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 119", "good-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 120", "badsign-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 121", "nosig-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 122", "baddata-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 123", "futuredate-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 124", "pastdate-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 125", "addedlater-A.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROOF},
	{"Test Case 126", "addedlater-AAAA.nosig-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROOF},
	{"Test Case 127", "good-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 128", "badsign-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 129", "nosig-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 130", "baddata-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 131", "futuredate-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 132", "pastdate-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 133", "good-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 134", "badsign-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 135", "nosig-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 136", "baddata-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 137", "futuredate-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 138", "pastdate-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 139", "addedlater-A.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROOF},
	{"Test Case 140", "addedlater-AAAA.nods-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROOF},
	{"Test Case 141", "good-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 142", "badsign-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 143", "nosig-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 144", "baddata-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 145", "futuredate-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 146", "pastdate-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 147", "good-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 148", "badsign-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 149", "nosig-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 150", "baddata-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 151", "futuredate-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 152", "pastdate-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 153", "addedlater-A.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROOF},
	{"Test Case 154", "addedlater-AAAA.futuredate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROOF},
	{"Test Case 155", "good-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 156", "badsign-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 156", "nosig-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 157", "baddata-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 158", "futuredate-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 159", "pastdate-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	VALIDATION_ERROR},
	{"Test Case 160", "good-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 161", "badsign-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 162", "nosig-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 163", "baddata-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 164", "futuredate-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 165", "pastdate-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	VALIDATION_ERROR},
	{"Test Case 166", "addedlater-A.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	BOGUS_PROOF},
	{"Test Case 167", "addedlater-AAAA.pastdate-ns.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	BOGUS_PROOF},
	{"Test Case 168", "addedlater-A.test.dnssec-tools.org", ns_c_in, 	ns_t_a, 	NONEXISTENT_NAME},
	{"Test Case 169", "addedlater-AAAA.test.dnssec-tools.org", ns_c_in, 	ns_t_aaaa, 	NONEXISTENT_NAME},
#endif


#if 0
	#if 1
	/* Test for resolution error (ensure no "search" in resolv.conf) */
	{"Checking name failure", "dns", ns_c_in, ns_t_a, DNS_ERROR_BASE+SR_SERVFAIL},
	#endif

	#if 1
	/* Test for non-existence */
	{"Checking non-existence proofs", "dns1.wesh.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a, NONEXISTENT_NAME}, 
	#endif

	#if 1
	/* Test for validation without recursion + CNAME */
	{"Testing CNAME and same-level validation", "apple.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a, VALIDATE_SUCCESS},
	#endif

	#if 1
	/* Test for validation with recursion */
	{"Testing validation up the chain", "dns.wesh.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a, VALIDATE_SUCCESS},
	#endif

	#if 1
	/* Test for multiple answers */
	{"Checking validation of multiple answers returned with ANY", "fruits.netsec.tislabs.com.", ns_c_in, ns_t_any, VALIDATE_SUCCESS},
	#endif

	#if 1
	/* Wild-card test */
	{"Checking validation with a wildcard match", "jackfruit.fruits.netsec.tislabs.com.", ns_c_in, ns_t_a, VALIDATE_SUCCESS},
	#endif

	#if 1
	/* Wild-card, non-existent type */
	{"Checking if wildcard with a different type matches", "jackfruit.fruits.netsec.tislabs.com.", ns_c_in, ns_t_cname, DNS_ERROR_BASE+SR_NO_ANSWER}, 
	#endif

	#if 0
	/* Test for bad class */
	{"Testing bad class", "dns.wesh.fruits.netsec.tislabs.com.", 15, ns_t_a, VALIDATE_SUCCESS},
	#endif
#endif

	{NULL, NULL, 0, 0},
};


void sendquery(const char *desc, const char *name, const u_int16_t class, const u_int16_t type, int result)
{
	int ret_val;
	
    struct query_chain *queries = NULL;
    struct assertion_chain *assertions = NULL;
    struct val_result *results = NULL;
	struct val_result *res;
    val_context_t *context;
    u_char name_n[MAXCDNAME];

	printf("%s\t", desc);

    if(NO_ERROR !=(ret_val = get_context(NULL, &context))) {
		printf("Error: %d\n", ret_val);		
        return;
	}

    if (ns_name_pton(name, name_n, MAXCDNAME-1) == -1) {
		printf("Error: %d\n", BAD_ARGUMENT);		
        return;
	}                                                                                                                 

	ret_val = resolve_n_check(context, name_n, type, class, 0,  
                                   &queries, &assertions, &results);

	if (ret_val != NO_ERROR) {
		printf ("FAILED: Error= %d\n", ret_val);
	}
	else {
		for (res=results; res; res=res->next) {
			if (res->status != result) {
				printf("FAILED: expected=%s(%d), received=%s(%d)\n", 
					p_val_error(result), result,
					p_val_error(res->status), res->status);
				val_print_assertion_chain(name_n, class, type, queries, results);
				goto end_test;
			}
		}

		printf("OK\n");
		val_print_assertion_chain(name_n, class, type, queries, results);
	}

end_test:	

    /* XXX De-register pending queries */
    free_query_chain(&queries);
    free_assertion_chain(&assertions);
    free_result_chain(&results);

    destroy_context(context);
}

void main()
{
	int i;
	for (i= 0 ; testcases[i].desc != NULL; i++) {
		sendquery(testcases[i].desc, testcases[i].qn, testcases[i].qc, testcases[i].qt, testcases[i].qr);
		printf("\n");
	}
}
