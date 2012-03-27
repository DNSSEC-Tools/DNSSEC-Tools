#! /usr/bin/env python

# #######################################################################
# Copyright (c) 2012, Bob Novas, Shinkuro, Inc.
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without 
# modification, are permitted provided that the following conditions 
# are met:
#
#  - Redistributions of source code must retain the above copyright  
#    notice, this list of conditions and the following disclaimer.
#
#  - Redistributions in binary form must reproduce the above copyright 
#    notice, this list of conditions and the following disclaimer in the 
#    documentation and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR 
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT 
# HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT 
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, 
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY 
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT 
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE 
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# #######################################################################

"""
test driver for dnsval.py - tests the dnssec-tools python wrapper
see http://dnssec-tools.org

$Id: test_dnsval.py 76 2012-02-15 20:51:03Z bob.novas $
"""

import sys
import unittest

from dnsval import Validator
from dnsval import VAL_QUERY_AC_DETAIL 
from dnsval import VAL_SUCCESS, VAL_AC_VERIFIED
from dnsval import VAL_CTX_FLAG_RESET, VAL_CTX_FLAG_SET
from dnsval import VAL_QUERY_DONT_VALIDATE, VAL_IGNORE_VALIDATION

# test names
VAL_NAME = "www.dnssec-tools.org"
BOGUS_NAME = "badsign-a.test.dnssec-tools.org"
PI_NAME = "good-A.insecure-ns.test.dnssec-tools.org"
VAL_DOE = "doesnotexist.test.dnssec-tools.org"
BOGUS_DOE = "nsectest.test.dnssec-tools.org"
PI_DOE = "doesnotexist.insecure-ns.test.dnssec-tools.org"

class TestValidator(unittest.TestCase):

    v = None

    # Create the validator context only once
    def createValidator(self):
        if self.v == None:
            self.v = Validator()


    # Check that internal definitions are consistent with library 
    def test_fmtStatusValues(self):
        
        self.createValidator()

        self.assertEqual(self.v.fmtValStatus(0x80), 'VAL_SUCCESS')
        self.assertEqual(self.v.fmtValStatus(1),    'VAL_BOGUS')
        self.assertEqual(self.v.fmtValStatus(0x88), 'VAL_PINSECURE')
    
        self.assertEqual(self.v.fmtAcStatus(VAL_AC_VERIFIED), 'VAL_AC_VERIFIED')


    # Convenience function for checking resolveAndCheck results
    def common_resolveAndCheck(self, nameval, classval, typeval, pResults):

        rrset = pResults.contents.val_rc_rrset.contents
        self.assertEqual(rrset.val_rrset_rcode, 0)
        self.assertEqual(rrset.val_rrset_name, nameval)
        self.assertEqual(rrset.val_rrset_class, classval)
        self.assertEqual(rrset.val_rrset_type, typeval)


    # test for the resolveAndCheck function
    def test_resolveAndCheck(self):
        
        self.createValidator()

        # test of a validatable name
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, 0) 
        if pResults:
            self.assertEqual(pResults.contents.val_rc_status, VAL_SUCCESS)
            self.common_resolveAndCheck(VAL_NAME, 1, 1, pResults)
            self.v.freeResultChain(pResults)

        # check if result details are returned 
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, VAL_QUERY_AC_DETAIL) 
        if pResults:
            self.assertEqual(pResults.contents.val_rc_status, VAL_SUCCESS)
            self.common_resolveAndCheck(VAL_NAME, 1, 1, pResults)
            self.assertTrue(pResults.contents.val_rc_answer)
            self.assertEqual(pResults.contents.val_rc_answer.contents.val_ac_status, VAL_AC_VERIFIED)
            self.v.freeResultChain(pResults)

        # check if query flags work 
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, VAL_QUERY_DONT_VALIDATE) 
        if pResults:
            self.assertEqual(pResults.contents.val_rc_status, VAL_IGNORE_VALIDATION)
            self.common_resolveAndCheck(VAL_NAME, 1, 1, pResults)
            self.v.freeResultChain(pResults)


    # test the setFlags function
    def test_setFlags(self):

        self.createValidator()

        # Disable validation
        self.v.setFlags(VAL_CTX_FLAG_SET, VAL_QUERY_DONT_VALIDATE)
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, 0) 
        if pResults:
            self.assertEqual(pResults.contents.val_rc_status, VAL_IGNORE_VALIDATION)
            self.v.freeResultChain(pResults)
            
        # Enable validation
        self.v.setFlags(VAL_CTX_FLAG_RESET, VAL_QUERY_DONT_VALIDATE)
        if pResults:
            pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, 0) 
            self.assertEqual(pResults.contents.val_rc_status, VAL_SUCCESS)
            self.v.freeResultChain(pResults)
    

    # test the isTrusted function
    def test_isTrusted(self):

        self.createValidator()

        # Check if secure name is trusted
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, 0)
        if pResults:
            self.assertTrue(self.v.isTrusted(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)
        
        # Check if bogus name is not trusted
        pResults = self.v.resolveAndCheck(BOGUS_NAME, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.isTrusted(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)

        # Check if provably insecure name is trusted 
        pResults = self.v.resolveAndCheck(PI_NAME, 1, 1, 0)
        if pResults:
            self.assertTrue(self.v.isTrusted(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)
        

    # test the isTrusted function
    def test_isValdated(self):

        self.createValidator()

        # Check if secure name is validated 
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, 0)
        if pResults:
            self.assertTrue(self.v.isValidated(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)
        
        # Check if bogus name is not validated 
        pResults = self.v.resolveAndCheck(BOGUS_NAME, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.isValidated(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)

        # Check if provably insecure name is not validated 
        pResults = self.v.resolveAndCheck(PI_NAME, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.isValidated(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)


    def test_doesNotExist(self):

        self.createValidator()

        # Non-Existence condition - bogus answers should not work, others should
        pResults = self.v.resolveAndCheck(VAL_DOE, 1, 1, 0)
        if pResults:
            self.assertTrue(self.v.doesNotExist(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)
        
        # NULL result
        pResults = self.v.resolveAndCheck(BOGUS_DOE, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.doesNotExist(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)

        pResults = self.v.resolveAndCheck(PI_DOE, 1, 1, 0)
        if pResults:
            self.assertTrue(self.v.doesNotExist(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)

        # Existence conditions - none of these should be true
        pResults = self.v.resolveAndCheck(VAL_NAME, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.doesNotExist(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)
        
        pResults = self.v.resolveAndCheck(BOGUS_NAME, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.doesNotExist(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)

        pResults = self.v.resolveAndCheck(PI_NAME, 1, 1, 0)
        if pResults:
            self.assertFalse(self.v.doesNotExist(pResults.contents.val_rc_status))
            self.v.freeResultChain(pResults)

        
if __name__ == "__main__":
    
    suite = unittest.TestLoader().loadTestsFromTestCase(TestValidator)
    unittest.TextTestRunner(verbosity=2).run(suite)
    
