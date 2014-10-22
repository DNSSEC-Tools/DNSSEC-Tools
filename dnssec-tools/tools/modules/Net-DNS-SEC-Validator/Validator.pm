#     Validator.pm -- Perl 5 interface to the DNSSEC-Tools validating resolver
#
#     written by G. S. Marzot (marz@users.sourceforge.net)
#
#     Copyright (c) 2006-2013 SPARTA, Inc.  All rights reserved.
#
#     Copyright (c) 2006-2009 G. S. Marzot. All rights reserved.
#
#
#     This program is free software; you can redistribute it and/or
#     modify it under the same terms as Perl itself.
#

package Net::DNS::SEC::Validator;
require Net::addrinfo;			# return type from getaddrinfo
require Net::hostent;			# return type from gethost*
use Net::DNS;				# to interpret DNS classes and types
use Carp;

our $VERSION = '1.13';   # current release version number
our $DNSSECTOOLSVERSION = "DNSSEC-Tools Version: 2.0";

use Exporter;
use DynaLoader;

sub AUTOLOAD {
    my $sub = $AUTOLOAD;
    (my $constname = $sub) =~ s/.*:://;
    my $val = constant($constname);
    if (not defined $val) {
	croak "Your vendor has not defined constant $constname";
    }
    *$sub = sub { $val }; # same as: eval "sub $sub { $val }";
    goto &$sub;
}

our @ISA = qw(Exporter DynaLoader);


our @EXPORT = qw(
    CTX_DYN_POL_RES_NRD
    CTX_DYN_POL_RES_OVR
    CTX_DYN_POL_VAL_OVR
	LIBSRES_NS_STAGGER
	LOG_ALERT
	LOG_CRIT
	LOG_DEBUG
	LOG_EMERG
	LOG_ERR
	LOG_INFO
	LOG_NOTICE
	LOG_WARNING
	MAX_PROOFS
	NS_MAXCDNAME
	ns_msg_getflag
	ns_t_dlv
	ns_t_dnskey
	ns_t_ds
	ns_t_nsec
	ns_t_nsec3
	ns_t_rrsig
	VAL_AC_DS_MISSING
	SOCKET
	SR_CALL_ERROR
	SR_DNS_GENERIC_ERROR
	SR_EDNS_VERSION_ERROR
	SR_FORMERR
	SR_HEADER_ERROR
	SR_INTERNAL_ERROR
	SR_MEMORY_ERROR
	SR_MKQUERY_INTERNAL_ERROR
	SR_NAME_EXPANSION_FAILURE
	SR_NO_ANSWER
	SR_NO_ANSWER_YET
	SR_NOTIMPL
	SR_NXDOMAIN
	SR_RCV_INTERNAL_ERROR
	SR_REFUSED
	SR_SEND_INTERNAL_ERROR
	SR_SERVFAIL
	SR_TSIG_ERROR
	SR_TSIG_INTERNAL_ERROR
	SR_UNSET
	SR_UNSUPP_EDNS0_LABEL
	SR_ZI_STATUS_LEARNED
	SR_ZI_STATUS_PERMANENT
	SR_ZI_STATUS_UNSET
	VAL_AC_ALGORITHM_NOT_SUPPORTED
	VAL_AC_BAD_BASE
	VAL_AC_BARE_RRSIG
	VAL_AC_CAN_VERIFY
	VAL_AC_DATA_MISSING
	VAL_AC_DNS_ERROR
	VAL_AC_DNSKEY_MISSING
	VAL_AC_DNSKEY_NOMATCH
	VAL_AC_DONT_GO_FURTHER
	VAL_AC_DS_MISSING
	VAL_AC_DS_NOMATCH
	VAL_AC_ERROR_BASE
	VAL_AC_FAIL_BASE
	VAL_AC_IGNORE_VALIDATION
	VAL_AC_INIT
	VAL_AC_INVALID_DS
	VAL_AC_INVALID_KEY
	VAL_AC_INVALID_RRSIG
	VAL_AC_LAST_BAD
	VAL_AC_LAST_ERROR
	VAL_AC_LAST_FAILURE
	VAL_AC_LAST_STATE
	VAL_AC_NEGATIVE_PROOF
	VAL_AC_NO_LINK
	VAL_AC_NOT_VERIFIED
	VAL_AC_PINSECURE
	VAL_AC_RRSIG_ALGORITHM_MISMATCH
	VAL_AC_RRSIG_EXPIRED
	VAL_AC_RRSIG_MISSING
	VAL_AC_RRSIG_NOTYETACTIVE
	VAL_AC_RRSIG_VERIFIED
	VAL_AC_RRSIG_VERIFIED_SKEW
	VAL_AC_RRSIG_VERIFY_FAILED
	VAL_AC_SIGNING_KEY
	VAL_AC_TRUST
	VAL_AC_TRUST_ANCHOR
	VAL_AC_TRUST_NOCHK
	VAL_AC_TRUST_POINT
	VAL_AC_UNKNOWN_ALGORITHM_LINK
	VAL_AC_UNKNOWN_DNSKEY_PROTOCOL
	VAL_AC_UNSET
	VAL_AC_UNTRUSTED_ZONE
	VAL_AC_VERIFIED
	VAL_AC_VERIFIED_LINK
	VAL_AC_WAIT_FOR_RRSIG
	VAL_AC_WAIT_FOR_TRUST
	VAL_AC_WCARD_VERIFIED
	VAL_AC_WCARD_VERIFIED_SKEW
	VAL_AC_WRONG_LABEL_COUNT
	VAL_AS_CB_COMPLETED
	VAL_AS_INFLIGHT
	VAL_AS_CTX_USER_SUPPLIED
	VAL_AS_DONE
	VAL_AS_IGNORE_CACHE
	VAL_AS_NO_ANSWERS
	VAL_AS_NO_CALLBACKS
	VAL_AS_NO_NEW_QUERIES
	VAL_BAD_ARGUMENT
	VAL_BARE_RRSIG
	VAL_INDETERMINATE
	VAL_BOGUS
	VAL_BOGUS_PROOF
	VAL_BOGUS_PROVABLE
	VAL_CONF_NOT_FOUND
	VAL_CONF_PARSE_ERROR
	VAL_DNS_ERROR
	VAL_DONT_KNOW
	VAL_EACCESS
	VAL_EINVAL
	VAL_ENOENT
	VAL_ENOMEM
	VAL_ENOSYS
	VAL_FLAG_CHAIN_COMPLETE
	VAL_FROM_ADDITIONAL
	VAL_FROM_ANSWER
	VAL_FROM_AUTHORITY
	VAL_FROM_QUERY
	VAL_FROM_UNSET
	VAL_IGNORE_VALIDATION
	VAL_INCOMPLETE_PROOF
	VAL_INTERNAL_ERROR
	VAL_IRRELEVANT_PROOF
	VAL_MASKED_FLAG_CHAIN_COMPLETE
	VAL_NO_ERROR
	VAL_NONEXISTENT_NAME
	VAL_NONEXISTENT_NAME_NOCHAIN
	VAL_NONEXISTENT_TYPE
	VAL_NONEXISTENT_TYPE_NOCHAIN
	VAL_NO_PERMISSION
	VAL_NO_POLICY
	VAL_NOT_IMPLEMENTED
	VAL_NOTRUST
	VAL_OOB_ANSWER
	VAL_OUT_OF_MEMORY
	VAL_PINSECURE
	VAL_PINSECURE_UNTRUSTED
	VAL_POL_GOPT_UNSET
	VAL_POL_GOPT_DISABLE
	VAL_POL_GOPT_ENABLE
	VAL_POL_GOPT_OVERRIDE
	VAL_QFLAGS_ANY
	VAL_QFLAGS_CACHE_MASK
	VAL_QFLAGS_NOCACHE_MASK
	VAL_QFLAGS_USERMASK
	VAL_QUERY_AC_DETAIL
	VAL_QUERY_DONT_VALIDATE
	VAL_QUERY_NO_DLV
	VAL_QUERY_USING_DLV
	VAL_QUERY_ASYNC
	VAL_QUERY_NO_EDNS0_FALLBACK
	VAL_QUERY_SKIP_RESOLVER
	VAL_QUERY_MARK_FOR_DELETION
	VAL_QUERY_IGNORE_SKEW
	VAL_QUERY_RECURSE
	VAL_QUERY_ITERATE
	VAL_QUERY_SKIP_CACHE
	VAL_QUERY_SKIP_ANS_CACHE
	VAL_QUERY_EDNS0_FALLBACK
	VAL_QUERY_GLUE_REQUEST
	VAL_QUERY_CHECK_ALL_RRSIGS
	VAL_RESOURCE_UNAVAILABLE
	VAL_SUCCESS
	VAL_TRUSTED_ANSWER
	VAL_UNTRUSTED_ANSWER
	VAL_UNTRUSTED_ZONE
	VAL_VALIDATED_ANSWER
	ZONE_USE_NOTHING
	ZONE_USE_TSIG
);

bootstrap Net::DNS::SEC::Validator;

sub new {       
    my $class = shift;
    my $self  = {};
    my %params = @_;

    @$self{keys %params} = values %params;

    $self->{policy} ||= undef; # passing NULL uses default policy

#    $self->{_ctx_ptr} = 
#    	Net::DNS::SEC::Validator::_create_context_with_conf(
#          $self->{policy},
#	      $self->{dnsval_conf},
#	      $self->{resolv_conf},
#  	      $self->{root_hints});
    $self->{_ctx_ptr} = 
    	Net::DNS::SEC::Validator::_create_context_ex($self);

    return undef unless $self->{_ctx_ptr};

    $self->{error} = 0;
    $self->{errorStr} = "";
    $self->{valStatus} = 0;
    $self->{valStatusStr} = "";

    bless($self, $class);
    return $self;
}

# wrapper around the ever changing Net::DNS API, who's authors refuse
# to leave things in a backward compatible way.
my $has_net_dns_parameters = eval 'require Net::DNS::Parameters';

sub typesbyname {
	if ($has_net_dns_parameters) {
		return Net::DNS::Parameters::typebyname(@_);
	} else {
		return Net::DNS::typesbyname(@_);
	}
}

sub classesbyname {
	if ($has_net_dns_parameters) {
		return Net::DNS::Parameters::classbyname(@_);
	} else {
		return Net::DNS::classesbyname(@_);
	}
}


# XXX unsupported so far
sub switch_policy {
    my $self = shift;
    my $label = shift;
    
    if (defined $label and $label ne $self->{policy}) {
	my $ctx_ptr =  $self->{_ctx_ptr};
	if (not defined $ctx_ptr) {
	    return $self->policy($label);
	} else {
        vc_DESTROY($self->{_ctx_ptr}) if $self->{_ctx_ptr};
	    $self->{_ctx_ptr} = 
		Net::DNS::SEC::Validator::_create_context_with_conf(
	           $self->{policy},
	           $self->{dnsval_conf},
	           $self->{resolv_conf},
    	           $self->{root_hints});
	    $self->{policy} = $label;
        }
    }
    return $self->{policy};
}

sub policy {
    my $self = shift;
    my $label = scalar(shift);

    if (defined $label and $label ne $self->{policy}) {
	# will discard old context and create new one with given label
    vc_DESTROY($self->{_ctx_ptr}) if $self->{_ctx_ptr};
	$self->{_ctx_ptr} = 
	    Net::DNS::SEC::Validator::_create_context_with_conf(
               $self->{policy},
	       $self->{dnsval_conf},
	       $self->{resolv_conf},
    	       $self->{root_hints});

	$self->{policy} = $label;    
    }
    return $self->{policy};
}

sub getaddrinfo
{
    my $self = shift;

    my $result = Net::DNS::SEC::Validator::_getaddrinfo($self,@_);

    $result = [] unless ref $result eq 'ARRAY';

    return (wantarray ? @{$result} : shift(@{$result}));
}

sub res_query {
    my $self = shift;
    my $dname = shift;
    my $class = shift;
    my $type = shift;

    $class ||= "IN";
    $type ||= "A";

    $class = classesbyname($class) unless $class =~ /^\d+$/;
    $type = typesbyname($type) unless $type =~ /^\d+$/;
    
    return Net::DNS::SEC::Validator::_res_query($self, $dname, $class, $type);
}

sub gethostbyname {
    my $self = shift;
    my $name = shift;
    my $af = shift;
    
    my $result = Net::DNS::SEC::Validator::_gethostbyname($self, $name, $af);

    return $result;
}

sub resolve_and_check {
    my $self = shift;
    my $dname = shift;
    my $class = shift;
    my $type = shift;
    my $flags = shift;

    $class ||= "IN";
    $type ||= "A";

    $class = classesbyname($class) unless $class =~ /^\d+$/;
    $type = typesbyname($type) unless $type =~ /^\d+$/;

    return Net::DNS::SEC::Validator::_resolve_and_check($self,
							$dname,
							$class,
							$type,
							$flags);
}

sub istrusted {
    my $self = shift;
    my $status = shift;

    $status = $self->{valStatus} unless defined $status;

    return Net::DNS::SEC::Validator::_istrusted($status);
}

sub isvalidated {
    my $self = shift;
    my $status = shift;

    $status = $self->{valStatus} unless defined $status;

    return Net::DNS::SEC::Validator::_isvalidated($status);
}

sub dnsval_conf {
    my $self = shift;
    my $file = shift;
    my $res;

    my $old = $self->{dnsval_conf} ||
	Net::DNS::SEC::Validator::_dnsval_conf_get();

    if ($file) {
	$res = Net::DNS::SEC::Validator::_dnsval_conf_set($file);
	undef $old if $res; # error case
    }
    return $old;
}

sub root_hints {
    my $self = shift;
    my $file = shift;
    my $res;

    my $old =  $self->{root_hints} ||
	Net::DNS::SEC::Validator::_root_hints_get();

    if ($file) {
	$res = Net::DNS::SEC::Validator::_root_hints_set($file);
	undef $old if $res; # error case
    }
    return $old;
}

sub resolv_conf {
    my $self = shift;
    my $file = shift;
    my $res;

    my $old =  $self->{resolv_conf} ||
	Net::DNS::SEC::Validator::_resolv_conf_get();

    if ($file) {
	$res = Net::DNS::SEC::Validator::_resolv_conf_set($file);
	undef $old if $res; # error case
    }
    return $old;
}

sub map_ns {
    my $self = shift;
    my $zone = shift;
    my $addr = shift;
    my $recursive = shift;
    
    my $result = Net::DNS::SEC::Validator::_ns_mapto_zone($self, $zone, 
                                                          $addr, $recursive);

    return $result;
}

sub valStatusStr {
    my $self = shift;
    my $status = shift;

    $status = $self->{valStatus} unless defined $status;

    return Net::DNS::SEC::Validator::_val_status($status);
}


sub async_submit {

    my $self = shift;
    my $domain = shift;
    my $class = shift;
    my $type = shift;
    my $flags = shift;
    my $cbref = shift;
    my $cbparam = shift;

    $class ||= "IN";
    $type ||= "A";

    $class = classesbyname($class) unless $class =~ /^\d+$/;
    $type = typesbyname($type) unless $type =~ /^\d+$/;

    return Net::DNS::SEC::Validator::_async_submit($self, $domain,
            $class, $type, $flags, $cbref, $cbparam);
}

sub async_gather {

    my $self = shift;
    my $desc_ref = shift;
    my $timeout = shift;

    my $ret = Net::DNS::SEC::Validator::_async_gather($self, $desc_ref,
            $timeout); 

    return $ret;
}

sub async_check {

    my $self = shift;
    my $desc_ref = shift;

    my $ret = Net::DNS::SEC::Validator::_async_check($self, $desc_ref); 

    return $ret;
}

sub async_gather_check_wait {

    my $self = shift;
    my $timeout = shift;

    my $ret = Net::DNS::SEC::Validator::_async_gather_check_wait($self,
            $timeout);

    return $ret;
}

sub DESTROY {
    my $self = shift;
    vc_DESTROY($self->{_ctx_ptr}) if $self->{_ctx_ptr};
}

1;
__END__

########################################################################

=pod

=head1 NAME

B<Net::DNS::SEC::Validator> - interface to B<libval(3)> and related constants, structures and functions

=head1 SYNOPSIS

  use Net::DNS::SEC::Validator;
  use Net::DNS::Packet;
  use Net::hostent;
  use Net::addrinfo;
  use Socket qw(:all);

  sub callback {

  }

  my $validator = new Net::DNS::SEC::Validator(policy => ":");
  $validator.map_ns("dnssec-tools.org", "127.0.0.1");
  my (@r) = $validator->getaddrinfo("good-A.test.dnssec-tools.org");
  my $r = $validator->res_query("dnssec-tools.org", "IN", "MX");
  my $h = $validator->gethostbyname("good-AAAA.test.dnssec-tools.org",
                                    AF_INET6);

  $validator->async_submit("badsign-a.test.dnssec-tools.org", 
        "IN", "A", 0, \&callback, undef);
  do {
    my $ref = $val->async_gather($readfds, $timeout);
    my $ret = $ref->[0];
    my $readfds = $ref->[1];
    my $timeout = $ref->[2];

    if (! @$readfds) {
        last;
    }

    my @readyarr = IO::Select->new(@$readfds)->can_read($timeout);
    $ret = $validator->async_check(\@readyarr);

  } while(1);   

=head1 DESCRIPTION

The B<Validator> module provides provides access to the B<libval(3)>
validating DNS resolver library.  The library functions are accessed through
an object-oriented interface.  The interface is designed to hide some of the
complexity of validating resolvers.  Application-interface behavior can be
customized through configuration files provided by B<libval>, and extensive
error codes are returned.

Since B<Validator> is a gateway to B<libval>, documentation for B<libval>
will provide further details on how the B<Validator> interfaces and parameters
may be used.

Details of DNSSEC and associated resolver behavior may be found in the core
DNSSEC RFCs (4033-4035).

=head1 INTERFACE
 
This module suppors both synchronous and ansynchronous lookups. A
description of the API follows.

=head2 B<Validator> Constructor

This constructor builds a new validator object, which is used to make the
various resolver calls.  When the validator object is created, a I<policy>
object is created.  The I<policy> object provides a number of settings that
will control various aspects of the DNS resolution.

To create a validator object use the I<Net::DNS::SEC::Validator->new()>
method.  This method takes a number of optional parameters, which will be
described below.

A policy object may be named with the I<policy> parameter, which associates
a label with a particular policy.  This allows that policy to be referenced
at a later time.  If the label isn't specified, then it will be given the
the default label from the B<libval> B<dnsval.conf> file.

The parameters to the constructor are passed as a hash, with both key and
value given in the call.  Besides the policy label, there are two sets of
constructor parameters.  These are separated based on how they are stored
and used in B<libval>.

=head3 Context Options

This group of parameters are stored in a I<val_context_opt> structure in
B<libval>.  This structure is defined in
B<dnssec/validator/include/validator/validator.h>.  The context options
below are the hash-key values used in the constructor call.

=over 4

=item I<dnsval_conf>

Configuration policy for the B<libval> library.

This file contains the validator policy.  The default value is
B</usr/local/etc/dnssec-tools/dnsval.conf>, but this may have been
changed when B<libval> was built and installed.

I<val_context_opt> field:  I<vc_val_conf>

=item I<nslist>

This is a list of name servers that should be used in resolving names.
This must be a white-space delimited list of IP or IPv6 addresses.

I<val_context_opt> field:  I<vc_nslist>

=item I<polflags>

This is a set of bitmapped policy flags.  The valid flags are defined in
B<dnssec/validator/include/validator/validator.h>.  The default value is
B<CTX_DYN_POL_RES_OVR>.

I<val_context_opt> field:  I<vc_polflags>

=item I<qflags>

This is the set of default query flags.  The valid flags are defined in
B<dnssec/validator/include/validator/validator.h>.  The default value is 0.

I<val_context_opt> field:  I<vc_qflags>

=item I<resolv_conf>

This file contains nameserver and search options for the B<libval> library.
The default value is B</usr/local/etc/dnssec-tools/resolv.conf>, but this may
have been changed when B<libval> was built and installed.

I<val_context_opt> field:  I<vc_res_conf>

=item I<root_hints>

This file contains bootstrapping information for the name resolver.
The default value is B</usr/local/etc/dnssec-tools/root.hints>, but this may
have been changed when B<libval> was built and installed.

I<val_context_opt> field:  I<vc_root_conf>

=item I<valpol>

This supplies a customized piece of validator configuration to the default
validator configuration as an extension or an override.  This is null by
default.

I<val_context_opt> field:  I<vc_valpol>

=back

=head3 Global Options

This group of parameters are stored in a I<val_global_opt> structure, which
is itself stored in a the I<gopt> field of the I<val_context_opt> structure.
This structure is defined in B<dnssec/validator/include/validator/validator.h>.
The global options below are the hash-key values used in the constructor call.

For all but the I<log_target> field, a value of -1 indicates an "ignore"
condition.  This means that the validator will not include dynamically
supplied global options with a value of -1 when creating its context.
This allows an application to override a subset of global options while
using the global options supplied in the B<dnsval.conf> file by default.

Even though B<libval> uses the global options in a separate structure from
the context options, they are all specified in the same hash when passed as
parameters to the B<Validator> constructor.

=over 4

=item I<app_policy>

This field is equivalent to the I<env-policy> option in a B<dnsval.conf>
file.  The following are the legal values and their I<env-policy>
equivalences:

    VAL_POL_GOPT_DISABLE       "disable"
    VAL_POL_GOPT_ENABLE        "enable"
    VAL_POL_GOPT_OVERRIDE      "override"

The default value is -1.

I<val_global_opt> field:  I<gopt.app_policy>

=item I<closest_ta_only>

This field is equivalent to the I<closest-ta-only> option in a B<dnsval.conf>
file.  Setting this to 1 is equivalent to setting I<closest-ta-only> to "yes";
setting it to 0 is equivalent to "no".  The default value is -1.

I<val_global_opt> field:  I<gopt.closest_ta_only>

=item I<edns0_size>

This field is equivalent to the I<edns0-size> option in a B<dnsval.conf>
file.  The default value is -1.

I<val_global_opt> field:  I<gopt.edns0_size>

=item I<env_policy>

This field is equivalent to the I<env-policy> option in a B<dnsval.conf>
file.  The following are the legal values and their I<env-policy>
equivalences:

    VAL_POL_GOPT_DISABLE       "disable"
    VAL_POL_GOPT_ENABLE        "enable"
    VAL_POL_GOPT_OVERRIDE      "override"

The default value is -1.

I<val_global_opt> field:  I<gopt.env_policy>

=item I<local_is_trusted>

This field is equivalent to the I<trust-oob-answers> option in a
B<dnsval.conf> file.  Setting this to 1 is equivalent to setting
I<trust-oob-answers> to "yes"; setting it to 0 is equivalent to "no".
The default value is -1.

I<val_global_opt> field:  I<gopt.local_is_trusted>

=item I<log_target>

This field allows the caller to specify additional log targets to those given
in the B<dnsval.conf> file.  No additional logs are listed by default.

I<val_global_opt> field:  I<gopt.log_target>

=item I<rec_fallback>

This field is equivalent to the I<rec-fallback> option in a B<dnsval.conf>
file.  Setting this to 1 is equivalent to setting I<rec-fallback> to "yes";
setting it to 0 is equivalent to "no".  The default value is -1.

I<val_global_opt> field:  I<gopt.rec_fallback>

=item I<max_refresh>

This field is equivalent to the I<max-refresh> option in a B<dnsval.conf>
file.  

I<val_global_opt> field:  I<gopt.max_refresh>

=item I<proto>

This field is equivalent to the I<proto> option in a B<dnsval.conf>
file. Setting this value to 1 is equivalent to setting I<proto> to
"ipv4"; setting this value to 2 is equivalent to setting I<proto> to
"ipv6". The default is 0, which is equivalent to setting I<proto> to
"any". 

I<val_global_opt> field:  I<gopt.proto>

=item I<timeout>

This field is equivalent to the I<timeout> option in a B<dnsval.conf>
file.  

I<val_global_opt> field:  I<gopt.timeout>

=item I<retry>

This field is equivalent to the I<retry> option in a B<dnsval.conf>
file.  

I<val_global_opt> field:  I<gopt.retry>


=back

=head3 Validator Result Fields

Operation status and results are found in the following validator fields:

  $validator->{error}        => the latest method error code
  $validator->{errorStr}     => the latest method error string
  $validator->{valStatus}    => the val_status of last call (if single)
  $validator->{valStatusStr} => the val_status string of last call

Values for these fields are described in the next section.


=head2 $validator->getaddrinfo(<name>[,<service>[,<hints>]])

=head3   where:

    <name> => is the node name or numeric address being queried
    <service> => is the name or number representing the service
    (note: <name> or <service> may be undef, but not both)
    <hint> => a Net::addrinfo object specifying flags, family, etc.

=head3   returns:

    An array of Net::addrinfo objects (augmented with a 'val_status'
    field). On error, returns an empty array. in scalar context
    returns first Net::addrinfo object, or undef on error.
                  

=head2 $validator->gethostbyname(<name>[,<family>])

=head3   where:

    <name> => is the node name or numeric address being queried
    <family> => the address family of returned entry (default: AF_INET)

=head3   returns:

    A Net::hostent object. Validator valStatus/valStatusStr fields
    will be updated. On error, undef is returned and validator object
    error/errorStr fields are updated.

                  
=head2 $validator->res_query(<name>[,<class>[,<type>]])

=head3   where:

    <name> 	=> is the node name or numeric address being queried
    <class> 	=> is the DNS class of the record being queried (default: IN)
    <type>	=> is the DNS record type being queried (default A)

=head3   returns:

    A packed DNS query result is returned on success. This object is
    suitable to be passed to the Net::DNS::Packet(\$result)
    interface for parsing. Validator valStatus/valStatusStr fields
    will be updated. On error, undef is returned and validator
    object error/errorStr fields are updated.


=head2 $validator->policy([<label>])

=head3   where:

    <label> 	=> the policy label to use (old context is destroyed)
    (default: ":" dnsval.conf default policy)

=head3   returns:

    the policy label currently (after change) being used.
                  

=head2 $validator->istrusted([<val_status>])

=head3   where:

    <val_status> => numeric validator status code
    (default: $validator->{valStatus})

=head3   returns:

    A boolean positive value if <val_status> is a trusted result.
                  

=head2 $validator->valStatusStr([<val_status>])

=head3   where:

    <val_status> => numeric validator status code
    (default: $validator->{valStatus})

=head3   returns:

    A string representation of the given <val_status>.
                  
=head2 $validator->map_ns(<zone>, <ipaddr>, <recursive>)

=head3   where:

    <zone> => string value for zone
    <ipaddr> => The IP address to which all queries associated with the
                above 'zone' should be directed.
    <recursive> => if set to 1, this name server is considered to
    recursive (queries are sent with the RD bit set). The default value
    is to consder the name server to be authoritative.

=head3   returns:

    0 if the association between the zone and the IP address could be
    made successfully; some other value if the association could not be
    created.
    

=head1 VALIDATOR DATA FIELDS

The validator's I<error> and I<errorStr> fields are set with values
corresponding to those from the standard I<herror()> and I<hstrerror()>
functions.  These values are defined in B<netdb.h>.  These values are:

  error      errorStr
    0        Resolver Error 0 (no error)
    1        Unknown host
    2        Host name lookup failure
    3        Unknown server error
    4        No address associated with name

The values for the validator's I<valStatus> field are defined in
B<.../dnssec-tools/validator/include/validator/val_errors.h>.  The values
for the I<valStatusStr> fields are the text representation of the status
values' constants.  The different possible values for I<valStatus> are
listed below, and further details are provided in B<libval(3)>:

    VAL_BARE_RRSIG
    VAL_INDETERMINATE
    VAL_BOGUS
    VAL_DNS_ERROR
    VAL_IGNORE_VALIDATION
    VAL_NONEXISTENT_NAME
    VAL_NONEXISTENT_NAME_NOCHAIN
    VAL_NONEXISTENT_TYPE
    VAL_NONEXISTENT_TYPE_NOCHAIN
    VAL_NOTRUST
    VAL_OOB_ANSWER
    VAL_PINSECURE
    VAL_PINSECURE_UNTRUSTED
    VAL_SUCCESS
    VAL_TRUSTED_ANSWER
    VAL_UNTRUSTED_ANSWER
    VAL_UNTRUSTED_ZONE
    VAL_VALIDATED_ANSWER

The I<istrusted()> and I<isvalidated()> functions can be used to test if
a particular I<valStatus> value corresponds to a trusted or a
validated status condition. Status values that are neither trusted nor
validated are un-trustworthy and must be treated as such by the 
application. 
                  
=head1 EXAMPLES

  use Net::DNS::SEC::Validator;
  use Net::DNS::Packet;
  use Net::hostent;
  use Net::addrinfo;
  use Socket qw(:all);
 
  # construct object
  my $validator = new Net::DNS::SEC::Validator(policy => ":");
 
  # change validation policy
  $validator->policy("validate_tools:");
 
  # fetch array of Net::addrinfo objects
  my (@r) = $validator->getaddrinfo("good-A.test.dnssec-tools.org");
  foreach $a (@r) {
     print $a->stringify, " is trusted\n"
 	if $validator->istrusted($a->val_status));
  }
 
  # query an MX record
  my $r = $validator->res_query("dnssec-tools.org", "IN", "MX");
  my ($pkt, $err) = new Net::DNS::Packet(\$r);
  print ($validator->istrusted ? 
 	"result is trusted\n" : 
 	"result is NOT trusted\n");
 
  my $h = $validator->gethostbyname("good-A.test.dnssec-tools.org");
  if ( @{$h->addr_list}) { 
  my $i;
     for $addr ( @{$h->addr_list} ) {
 	printf "\taddr #%d is [%s]\n", $i++, inet_ntoa($addr);
     } 
  }

  # get details of validation
  my $a = $validator->resolve_and_check("good-a.test.dnssec-tools.org", "IN", "A", 0);
  foreach my $h (@$a) {
   print "Status: " .  ${$h}{status} . "\n"; 
   print ($validator->istrusted(${$h}{status}) ? 
           "result is trusted\n" : 
           "result is NOT trusted\n");

   $acs = ${$h}{answer}; 
   foreach my $ac ($acs) {
        print "AC status: " . ${$ac}{status} . "\n";
        $acr = ${$ac}{rrset};
        $acd = ${$acr}{data};
        foreach $d (@$acd) {
            print "Data RR status: " . ${$d}{rrstatus} . "\n";
            ${$d}{rrdata}->print;
        }
        $acs = ${$acr}{sigs};
        foreach $d (@$acs) {
            print "Sig RR status: " . ${$d}{rrstatus} . "\n";
            ${$d}{rrdata}->print;
        }
   } 
}

=head1 SEE ALSO

B<libval(3)>,
B<dnsval.conf(3)>,
B<resolv.conf(3)>,
B<root.hints(3)>


=head1 COPYRIGHT

Copyright (c) 2006 G. S. Marzot. All rights reserved.  This program
is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

Copyright (c) 2006-2013 SPARTA, Inc.  All Rights Reserved.  This program
is free software; you can redistribute it and/or modify it under
the same terms as Perl itself.

=head1 AUTHOR

 G. S. Marzot (marz@users.sourceforge.net)

=cut

