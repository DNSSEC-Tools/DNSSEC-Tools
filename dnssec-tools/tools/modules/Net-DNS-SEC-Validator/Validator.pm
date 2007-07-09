#     Validator.pm -- Perl 5 interface to the Dnssec-Tools validating resolver
#
#     written by G. S. Marzot (marz@users.sourceforge.net)
#
#     Copyright (c) 2006-2007 SPARTA, Inc.  All rights reserved.
#
#     Copyright (c) 2006-2007 G. S. Marzot. All rights reserved.
#
#
#     This program is free software; you can redistribute it and/or
#     modify it under the same terms as Perl itself.
#
package Net::DNS::SEC::Validator;
require Net::addrinfo; # return type from getaddrinfo
require Net::hostent; # return type from gethost*
use Net::DNS; # to interpret DNS classes and types
use Carp;

our $VERSION = '1.20';   # current release version number

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

our @EXPORT = qw(ALG_DH ALG_DSASHA1 ALG_DS_HASH_SHA1 ALG_NSEC3_DSASHA1
	       ALG_NSEC3_HASH_SHA1 ALG_NSEC3_RSASHA1 ALG_NSEC_HASH_SHA1
	       ALG_RSAMD5 ALG_RSASHA1 CANNOT_BE_USED CAN_SIGN_KEY CAN_SIGN_ZONE
	       CAN_SIGN_ZONE_AND_KEY DNAME_MAX DNS_PORT EDNS_UDP_SIZE ENVELOPE
	       MAXDNAME MAX_ALIAS_CHAIN_LENGTH MAX_GLUE_FETCH_DEPTH MAX_PROOFS
	       NSEC3_FLAG_OPTOUT NS_CMPRSFLGS NS_INT16SZ NS_INT32SZ
	       NS_MAXCDNAME NS_MAXDNAME NS_PUT16 NS_PUT32
	       QUERY_BAD_CACHE_THRESHOLD QUERY_BAD_CACHE_TTL Q_ANSWERED
	       Q_CONFLICTING_ANSWERS Q_ERROR_BASE Q_INIT Q_MISSING_GLUE
	       Q_QUERY_ERROR Q_REFERRAL_ERROR Q_RESPONSE_ERROR Q_SENT
	       Q_WAIT_FOR_GLUE Q_WRONG_ANSWER RES_RETRY RES_USE_DNSSEC
	       RRSIGLABEL SHA_DIGEST_LENGTH SIGNBY SR_ANS_BARE_RRSIG
	       SR_ANS_CNAME SR_ANS_DNAME SR_ANS_NACK SR_ANS_STRAIGHT
	       SR_ANS_UNSET SR_CALL_ERROR SR_CRED_AUTH_ADD SR_CRED_AUTH_ANS
	       SR_CRED_AUTH_AUTH SR_CRED_FILE SR_CRED_NONAUTH_ADD
	       SR_CRED_NONAUTH_ANS SR_CRED_NONAUTH_AUTH SR_CRED_UNSET
	       SR_DNS_GENERIC_ERROR SR_EDNS_VERSION_ERROR SR_FORMERR
	       SR_HEADER_ERROR SR_INTERNAL_ERROR SR_MEMORY_ERROR
	       SR_MKQUERY_INTERNAL_ERROR SR_NAME_EXPANSION_FAILURE SR_NOTIMPL
	       SR_NO_ANSWER SR_NO_ANSWER_YET SR_NXDOMAIN SR_RCV_INTERNAL_ERROR
	       SR_REFUSED SR_SEND_INTERNAL_ERROR SR_SERVFAIL SR_TSIG_ERROR
	       SR_TSIG_INTERNAL_ERROR SR_UNSET SR_UNSUPP_EDNS0_LABEL
	       SR_ZI_STATUS_LEARNED SR_ZI_STATUS_PERMANENT SR_ZI_STATUS_UNSET
	       TTL VALIDATOR_LOG_PORT VAL_AC_ALGORITHM_NOT_SUPPORTED
	       VAL_AC_BAD_BASE VAL_AC_BAD_DELEGATION VAL_AC_BARE_RRSIG
	       VAL_AC_CAN_VERIFY VAL_AC_DATA_MISSING VAL_AC_DNSKEY_MISSING
	       VAL_AC_DNSKEY_NOMATCH VAL_AC_DNS_CONFLICTING_ANSWERS
	       VAL_AC_DNS_MISSING_GLUE VAL_AC_DNS_QUERY_ERROR
	       VAL_AC_DNS_REFERRAL_ERROR VAL_AC_DNS_RESPONSE_ERROR
	       VAL_AC_DNS_WRONG_ANSWER VAL_AC_DONT_GO_FURTHER VAL_AC_DS_MISSING
	       VAL_AC_ERROR_BASE VAL_AC_FAIL_BASE VAL_AC_IGNORE_VALIDATION
	       VAL_AC_INIT VAL_AC_INVALID_KEY VAL_AC_INVALID_RRSIG
	       VAL_AC_LAST_BAD VAL_AC_LAST_ERROR VAL_AC_LAST_FAILURE
	       VAL_AC_LAST_STATE VAL_AC_NEGATIVE_PROOF VAL_AC_NOT_VERIFIED
	       VAL_AC_NO_TRUST_ANCHOR VAL_AC_PROVABLY_UNSECURE
	       VAL_AC_RRSIG_ALGORITHM_MISMATCH VAL_AC_RRSIG_EXPIRED
	       VAL_AC_RRSIG_MISSING VAL_AC_RRSIG_NOTYETACTIVE
	       VAL_AC_RRSIG_VERIFIED VAL_AC_RRSIG_VERIFIED_SKEW
	       VAL_AC_RRSIG_VERIFY_FAILED VAL_AC_SIGNING_KEY
	       VAL_AC_TRUSTED_ZONE VAL_AC_TRUST_KEY
	       VAL_AC_UNKNOWN_ALGORITHM_LINK VAL_AC_UNKNOWN_DNSKEY_PROTOCOL
	       VAL_AC_UNSET VAL_AC_UNTRUSTED_ZONE VAL_AC_VERIFIED
	       VAL_AC_VERIFIED_LINK VAL_AC_WAIT_FOR_RRSIG VAL_AC_WAIT_FOR_TRUST
	       VAL_AC_WCARD_VERIFIED VAL_AC_WCARD_VERIFIED_SKEW
	       VAL_AC_WRONG_LABEL_COUNT VAL_BAD_ARGUMENT
	       VAL_BAD_PROVABLY_UNSECURE VAL_BARE_RRSIG VAL_BOGUS
	       VAL_BOGUS_PROOF VAL_BOGUS_PROVABLE VAL_BOGUS_UNPROVABLE
	       VAL_CONF_NOT_FOUND VAL_CONF_PARSE_ERROR VAL_CTX_IDLEN
	       VAL_DNS_CONFLICTING_ANSWERS VAL_DNS_MISSING_GLUE
	       VAL_DNS_QUERY_ERROR VAL_DNS_REFERRAL_ERROR
	       VAL_DNS_RESPONSE_ERROR VAL_DNS_WRONG_ANSWER VAL_DONT_GO_FURTHER
	       VAL_DONT_KNOW VAL_EACCESS VAL_EINVAL VAL_ENOENT VAL_ENOMEM
	       VAL_ENOSYS VAL_FLAG_CHAIN_COMPLETE VAL_FROM_ADDITIONAL
	       VAL_FROM_ANSWER VAL_FROM_AUTHORITY VAL_FROM_QUERY VAL_FROM_UNSET
	       VAL_IGNORE_VALIDATION VAL_INCOMPLETE_PROOF VAL_INTERNAL_ERROR
	       VAL_IRRELEVANT_PROOF VAL_LOCAL_ANSWER VAL_LOG_OPTIONS
	       VAL_MASKED_FLAG_CHAIN_COMPLETE VAL_NONEXISTENT_NAME
	       VAL_NONEXISTENT_NAME_NOCHAIN VAL_NONEXISTENT_NAME_OPTOUT
	       VAL_NONEXISTENT_TYPE VAL_NONEXISTENT_TYPE_NOCHAIN VAL_NOTRUST
	       VAL_NOT_IMPLEMENTED VAL_NO_ERROR VAL_NO_PERMISSION VAL_NO_POLICY
	       VAL_OUT_OF_MEMORY VAL_PROVABLY_UNSECURE
	       VAL_QFLAGS_AFFECTS_CACHING VAL_QFLAGS_ANY VAL_QFLAGS_USERMASK
	       VAL_QUERY_DONT_VALIDATE VAL_QUERY_GLUE_REQUEST
	       VAL_QUERY_MERGE_RRSETS VAL_QUERY_NO_DLV VAL_QUERY_USING_DLV
	       VAL_RESOURCE_UNAVAILABLE VAL_SUCCESS VAL_TRUSTED_ANSWER
	       VAL_TRUSTED_ZONE VAL_UNTRUSTED_ANSWER VAL_UNTRUSTED_ZONE
	       VAL_VALIDATED_ANSWER VAL_VERIFIED_CHAIN ZONE_USE_NOTHING
	       ZONE_USE_TSIG  ns_t_dlv ns_t_dnskey ns_t_ds
	       ns_t_nsec ns_t_nsec3 ns_t_rrsig
	      );

bootstrap Net::DNS::SEC::Validator;

sub new {       
    my $class = shift;
    my $self  = {};
    my %params = @_;

    @$self{keys %params} = values %params;

    $self->{policy} ||= undef; # passing NULL uses default policy

    $self->{_ctx_ptr} = 
	Net::DNS::SEC::Validator::_create_context_with_conf(
	   $self->{policy},
	   $self->{dnsval_conf},
	   $self->{resolv_conf},
    	   $self->{root_hints});

    return undef unless $self->{_ctx_ptr};

    $self->{error} = 0;
    $self->{errorStr} = "";
    $self->{valStatus} = 0;
    $self->{valStatusStr} = "";

    bless($self, $class);
    return $self;
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

    $class = Net::DNS::classesbyname($class) unless $class =~ /^\d+$/;
    $type = Net::DNS::typesbyname($type) unless $type =~ /^\d+$/;
    
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

    $class = Net::DNS::classesbyname($class) unless $class =~ /^\d+$/;
    $type = Net::DNS::typesbyname($type) unless $type =~ /^\d+$/;

    $flags ||= VAL_QUERY_MERGE_RRSETS;

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

sub valStatusStr {
    my $self = shift;
    my $status = shift;

    $status = $self->{valStatus} unless defined $status;

    return Net::DNS::SEC::Validator::_val_status($status);
}

sub DESTROY {
    my $self = shift;

}

1;
__END__

=head1 NAME

    Net::DNS::SEC::Validator - interface to libval(3) and related constants, structures and functions.

=head1 SYNOPSIS

 use Net::DNS::SEC::Validator;
 use Net::DNS::Packet;
 use Net::hostent;
 use Net::addrinfo;
 use Socket qw(:all);

 my $validator = new Net::DNS::SEC::Validator(policy => ":");
 my (@r) = $validator->getaddrinfo("good-A.test.dnssec-tools.org");
 my $r = $validator->res_query("marzot.net", "IN", "MX");
 my $h = $validator->gethostbyname("good-AAAA.test.dnssec-tools.org",
    AF_INET6);

=head1 DESCRIPTION

This Perl module is designed to implement and export functionality
provided by the validating DNS resolver library, libval(3). The
functions are provided through an easy-to-use object oriented
interface. The interface is designed for the higher level user, hiding
some of the complexity of validating resolvers. Nevertheless,
application interface behavior can be customized through configuration
files provided by libval(3) and extensive error codes returned.

Details of DNSSEC and associated resolver behavior may be found in the
core DNSSEC RFCs (4033-4035).

=head1 INTERFACE:
 
A description of the API follows:

=head2 Contructor:

To create a validator object use the Net::DNS::SEC::Validator->new()
method. This method optionally takes a policy label (policy =>
'label'), or default to using the default label in the libval(3)
dnsval.conf file.

=head2 Data Fields:

 $validator->{error} =>The latest method error code
 $validator->{errorStr} => the latest method error string
 $validator->{valStatus} => the val_status of last call (if single)
 $validator->{valStatusStr} => the val_status string of last call


=head2 Methods:


=head2 $validator->getaddrinfo(<name>[,<service>[,<hints>]])

=head3   where:

    <name> => is the node name or numeric address being queried
    <service> => is the name or number represting the service
    (note: <name> or <service> may be undef, but not both)
    <hint> => a Net::addrinfo object specying flags, family, etc.

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
    <type>	=> is the DNS record type being queried (defailt A)

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

    <val_status> => numeric vaildator status code
    (default: $validator->{valStatus})

=head3   returns:

    A boolean positive value if <val_status> is a trusted result.
                  

=head2 $validator->valStatusStr([<val_status>])

=head3   where:

    <val_status> => numeric vaildator status code
    (default: $validator->{valStatus})

=head3   returns:

    A string representation of the given <val_status>.
                  

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
  my $r = $validator->res_query("marzot.net", "IN", "MX");
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

=head1 COPYRIGHT

   Copyright (c) 2006 G. S. Marzot. All rights reserved.  This program
   is free software; you can redistribute it and/or modify it under
   the same terms as Perl itself.

   Copyright (c) 2006 SPARTA, Inc.  All Rights Reserved.  This program
   is free software; you can redistribute it and/or modify it under
   the same terms as Perl itself.

=head1 AUTHOR

 G. S. Marzot (marz@users.sourceforge.net)

=cut
