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
dnsval.py - wraps the dnssec-tools libval-threads library.
see http://dnssec-tools.org

$Id: dnsval.py 76 2012-02-15 20:51:03Z bob.novas $
"""


from ctypes import CDLL, POINTER, RTLD_GLOBAL, Structure
from ctypes import c_char_p, c_char, c_int, c_ushort, c_ubyte, c_uint, c_ulong, c_void_p
from ctypes import byref, cast, create_string_buffer, pointer, sizeof, c_size_t
from ctypes import c_int8,  c_int16,  c_int32,  c_int64
from ctypes import c_uint8, c_uint16, c_uint32, c_uint64

import os
import sys

# validator flags
VAL_QUERY_AC_DETAIL         = 0x00000001
VAL_QUERY_DONT_VALIDATE     = 0x00000002
VAL_QUERY_NO_DLV            = 0x00000004
VAL_QUERY_USING_DLV         = 0x00000008
VAL_QUERY_ASYNC             = 0x00000010
VAL_QUERY_NO_EDNS0_FALLBACK = 0x00000020
VAL_QUERY_SKIP_RESOLVER     = 0x00000040
VAL_QUERY_MARK_FOR_DELETION = 0x00000080
VAL_QUERY_IGNORE_SKEW       = 0x00000100
VAL_QUERY_RECURSE           = 0x00010000
VAL_QUERY_SKIP_CACHE        = 0x00020000

# validator error codes
VAL_NOT_IMPLEMENTED         = -1
VAL_RESOURCE_UNAVAILABLE    = -2
VAL_BAD_ARGUMENT            = -3
VAL_INTERNAL_ERROR          = -4
VAL_NO_PERMISSION           = -5
VAL_CONF_PARSE_ERROR        = -6
VAL_CONF_NOT_FOUND          = -7
VAL_NO_POLICY               = -8

VAL_AC_VERIFIED             = 31

# validator result codes

VAL_FLAG_CHAIN_COMPLETE     = 0x80

VAL_SUCCESS                         =  0 | VAL_FLAG_CHAIN_COMPLETE
VAL_BOGUS                           =  1 
VAL_DNS_ERROR                       =  2
VAL_INDETERMINATE                   =  3
VAL_NOTRUST                         =  4
VAL_NONEXISTENT_NAME                =  5 | VAL_FLAG_CHAIN_COMPLETE
VAL_NONEXISTENT_TYPE                =  6 | VAL_FLAG_CHAIN_COMPLETE
VAL_NONEXISTENT_NAME_NOCHAIN        =  7 | VAL_FLAG_CHAIN_COMPLETE
VAL_NONEXISTENT_TYPE_NOCHAIN        =  8 | VAL_FLAG_CHAIN_COMPLETE
VAL_NONEXISTENT_PINSECURE           =  9 | VAL_FLAG_CHAIN_COMPLETE
VAL_NONEXISTENT_PINSECURE_UNTRUSTED = 10 | VAL_FLAG_CHAIN_COMPLETE
VAL_BARE_RRSIG                      = 11 | VAL_FLAG_CHAIN_COMPLETE
VAL_IGNORE_VALIDATION               = 12 | VAL_FLAG_CHAIN_COMPLETE
VAL_UNTRUSTED_ZONE                  = 13 | VAL_FLAG_CHAIN_COMPLETE
VAL_OOB_ANSWER                      = 14 | VAL_FLAG_CHAIN_COMPLETE
VAL_TRUSTED_ANSWER                  = 15 | VAL_FLAG_CHAIN_COMPLETE
VAL_VALIDATED_ANSWER                = 16 | VAL_FLAG_CHAIN_COMPLETE
VAL_UNTRUSTED_ANSWER                = 17 | VAL_FLAG_CHAIN_COMPLETE

# action codes
VAL_CTX_FLAG_SET                    = 0x01
VAL_CTX_FLAG_RESET                  = 0x02


val_context_t = c_void_p
val_status_t  = c_uint8
val_astatus_t = c_uint16
val_log_t     = c_void_p

MAX_PROOFS = 4
NS_MAXDNAME = 1025

class ValidatorException(Exception):
    """
    Raised if one of the libval API returns an error, but they 
    don't seem to.
    """
    def __init__(self, reason):
        super(ValidatorException, self).__init__()
        self.reason = reason

class val_rr_rec(Structure):
    pass

val_rr_rec._fields_ = \
    [("rr_rdata_length",      c_size_t),
     ("rr_data",              POINTER(c_ubyte)),
     ("rr_next",              POINTER(val_rr_rec)),
     ("rr_status",            val_astatus_t)]

class sockaddr_storage(Structure):
    pass

sockaddr_storage._fields = \
    [('ss_family', c_ushort),
     ('__ss_pad1', c_char * 6),
     ('__ss_align', c_int64),
     ('__ss_pad2', c_char * 112)]

class val_rrset_rec(Structure):
    pass

val_rrset_rec._fields_ = \
    [("val_rrset_rcode",      c_int32),
     ("val_rrset_name",       c_char * NS_MAXDNAME),
     ("val_rrset_class",      c_int32),
     ("val_rrset_type",       c_int32),
     ("val_rrset_ttl",        c_int64),
     ("val_rrset_section",    c_int32),
     ("val_rrset_server",     sockaddr_storage),
     ("val_rrset_data",       POINTER(val_rr_rec)),
     ("val_rrset_sig",        POINTER(val_rr_rec))]

class val_authentication_chain(Structure):
    pass

val_authentication_chain._fields_ = \
    [("val_ac_status",        val_astatus_t),
     ("val_ac_rrset",         POINTER(val_rrset_rec)),
     ("val_ac_trust",         POINTER(val_authentication_chain))]

class val_result_chain(Structure):
    pass

val_result_chain._fields_ = \
    [("val_rc_status",        val_status_t),
     ("val_rc_alias",         c_char_p),
     ("val_rc_rrset",         POINTER(val_rrset_rec)),
     ("val_rc_answer",        POINTER(val_authentication_chain)),
     ("val_rc_proof_count",   c_int32),
     ("val_rc_proofs",        POINTER(val_authentication_chain * MAX_PROOFS)),
     ("val_rc_next",          POINTER(val_result_chain))]


class Validator(object):
    """
    wraps libval-threads methods discussed in man libval(3).
    """
    
    def __init__(self, label=None):

        #Get a handle to the shared libraries. 
        if sys.platform == 'win32':
            #Windows
            CDLL('libsres.dll', RTLD_GLOBAL)
            libval  = CDLL('libval-threads.dll')
        elif sys.platform == 'darwin':
            #mac
            CDLL('libcrypto.dylib', RTLD_GLOBAL)
            CDLL('libsres.dylib', RTLD_GLOBAL)
            libval    = CDLL('libval-threads.dylib')
        elif sys.platform == 'linux2':
            #linux
            CDLL('libsres.so', RTLD_GLOBAL)
            libval  = CDLL('libval-threads.so')
        else:
            raise ValidatorException("Unknown platform - %s" % (sys._platform, ))
        
        #build the calls to libval-threads functions
        
        #val_create_context
        self._create_context = libval.val_create_context
        self._create_context.restype = c_int
        self._create_context.argtypes = [c_char_p, POINTER(POINTER(val_context_t))]
        
        #val_free_context
        self._free_context = libval.val_free_context
        self._free_context.restype = None
        self._free_context.argtypes = [POINTER(val_context_t)]
        
        #val_resolve_and_check
        self._resolve_and_check = libval.val_resolve_and_check
        self._resolve_and_check.restype = c_int
        self._resolve_and_check.argtypes = [POINTER(val_context_t), c_char_p, c_int, c_int, c_uint, POINTER(POINTER(val_result_chain))]

        #val_free_result_chain
        self._free_result_chain = libval.val_free_result_chain
        self._free_result_chain.restype = None
        self._free_result_chain.argtypes = [POINTER(val_result_chain)]

        #val_context_setqflags
        self._val_context_setqflags = libval.val_context_setqflags
        self._val_context_setqflags.restype = c_int
        self._val_context_setqflags.argtypes = [POINTER(val_context_t), c_uint8, c_uint32]

        #val_istrusted
        self._val_istrusted = libval.val_istrusted
        self._val_istrusted.restype = c_int
        self._val_istrusted.argtypes = [val_status_t]

        #val_isvalidated
        self._val_isvalidated = libval.val_isvalidated
        self._val_isvalidated.restype = c_int
        self._val_isvalidated.argtypes = [val_status_t]

        #val_does_not_exist
        self._val_does_not_exist = libval.val_does_not_exist
        self._val_does_not_exist.restype = c_int
        self._val_does_not_exist.argtypes = [val_status_t]
        
        #p_val_status
        self._p_val_status = libval.p_val_status
        self._p_val_status.restype = c_char_p
        self._p_val_status.argtypes = [val_status_t]
        
        #p_ac_status
        self._p_ac_status = libval.p_ac_status
        self._p_ac_status.restype = c_char_p
        self._p_ac_status.argtypes = [val_astatus_t]
                
        #p_val_error is #define'd as p_val_status
        self._p_val_error = self._p_val_status
        
        #p_val_log_add_optarg
        self._val_log_add_optarg = libval.val_log_add_optarg
        self._val_log_add_optarg.restype = val_log_t
        self._val_log_add_optarg.argtypes = [c_char_p, c_int32]
      
        contextBuf = create_string_buffer(sizeof(val_context_t))
        self.pContext = cast(contextBuf, POINTER(val_context_t))
        status = self._create_context(label, byref(self.pContext)) 
        if status != 0:
            raise ValidatorException(status)        

    def __del__(self):
        """
        free the context returned by createContext.
        """
        self._free_context(self.pContext)
    
      
    def setFlags(self, action, flags):
        """
        set/reset validator flags on context
        (so you don't have to pass them in resolveAndCheck calls)
        """
        return self._val_context_setqflags(self.pContext, action, flags)
        
    def resolveAndCheck(self, domainName, rdclass, rdtype, flags=0):
        """
        resolve a domain and check its dnssec validity.
        """
        pResultsBuf = create_string_buffer(sizeof(val_result_chain))
        pResults = cast(pResultsBuf, POINTER(val_result_chain))
        status = self._resolve_and_check(self.pContext, domainName, rdclass, rdtype, flags, byref(pResults))
        if status != 0:
            raise ValidatorException(status)
        return pResults
    
    def freeResultChain(self, pResults):
        """
        free the result chain returned by resolveAndCheck.
        """
        self._free_result_chain(pResults)
        
    def isTrusted(self, status):
        """
        check val_status_t type for trusted.
        """
        return self._val_istrusted(status)
    
    def isValidated(self, status):
        """
        check val_status_t type for validated.
        """
        return self._val_isvalidated(status)
    
    def doesNotExist(self, status):
        """
        check val_status_t type for non-existence.
        """
        return self._val_does_not_exist(status)
    
    def fmtValStatus(self, valStatus):
        """
        format a val_status_t object.
        """
        return self._p_val_status(valStatus)
    
    def fmtAcStatus(self, valAcStatus):
        """
        format a val_astatus_t object.
        """
        return self._p_ac_status(valAcStatus)
    
    def logAddOptarg(self, args, useStderr):
        """
        set optional args on the validator logging.
        """
        return self._val_log_add_optarg(args, useStderr)
