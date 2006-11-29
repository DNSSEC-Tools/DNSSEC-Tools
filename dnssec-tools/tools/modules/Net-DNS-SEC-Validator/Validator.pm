package Net::DNS::SEC::Validator;
use Net::DNS; # to interpret DNS classes and types
use Carp;

our $VERSION = '0.10a';   # current release version number

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

our @EXPORT_OK = qw(ALG_DH ALG_DSASHA1 ALG_DS_HASH_SHA1 ALG_NSEC3_DSASHA1
	       ALG_NSEC3_HASH_SHA1 ALG_NSEC3_RSASHA1 ALG_NSEC_HASH_SHA1
	       ALG_RSAMD5 ALG_RSASHA1 CANNOT_BE_USED CAN_SIGN_KEY CAN_SIGN_ZONE
	       CAN_SIGN_ZONE_AND_KEY DNAME_MAX DNS_PORT EDNS_UDP_SIZE ENVELOPE
	       MAXDNAME MAX_ALIAS_CHAIN_LENGTH MAX_PROOFS NS_CMPRSFLGS
	       NS_INT16SZ NS_INT32SZ NS_MAXCDNAME NS_MAXDNAME NS_PUT16 NS_PUT32
	       Q_ANSWERED Q_ERROR_BASE Q_INIT Q_SENT Q_WAIT_FOR_GLUE RES_RETRY
	       RES_USE_DNSSEC RRSIGLABEL SHA_DIGEST_LENGTH SIGNBY
	       SIG_ACCEPT_WINDOW SR_ANS_BARE_RRSIG SR_ANS_CNAME SR_ANS_DNAME
	       SR_ANS_NACK_NSEC SR_ANS_NACK_NSEC3 SR_ANS_NACK_SOA
	       SR_ANS_STRAIGHT SR_ANS_UNSET SR_CALL_ERROR
	       SR_CONFLICTING_ANSWERS SR_CRED_AUTH_ADD SR_CRED_AUTH_ANS
	       SR_CRED_AUTH_AUTH SR_CRED_FILE SR_CRED_NONAUTH_ADD
	       SR_CRED_NONAUTH_ANS SR_CRED_NONAUTH_AUTH SR_CRED_UNSET
	       SR_DNS_GENERIC_ERROR SR_EDNS_VERSION_ERROR SR_FORMERR
	       SR_HEADER_BADSIZE SR_INTERNAL_ERROR SR_LAST_ERROR
	       SR_MEMORY_ERROR SR_MISSING_GLUE SR_MKQUERY_INTERNAL_ERROR
	       SR_NAME_EXPANSION_FAILURE SR_NOTIMPL SR_NO_ANSWER
	       SR_NO_ANSWER_YET SR_NXDOMAIN SR_RCV_INTERNAL_ERROR
	       SR_REFERRAL_ERROR SR_REFUSED SR_SEND_INTERNAL_ERROR SR_SERVFAIL
	       SR_TSIG_ERROR SR_TSIG_INTERNAL_ERROR SR_UNSET
	       SR_UNSUPP_EDNS0_LABEL SR_WRONG_ANSWER SR_ZI_STATUS_LEARNED
	       SR_ZI_STATUS_PERMANENT SR_ZI_STATUS_UNSET TTL VALIDATOR_LOG_PORT
	       VAL_AC_ALGORITHM_NOT_SUPPORTED VAL_AC_ALGORITHM_REFUSED
	       VAL_AC_BAD_BASE VAL_AC_BAD_DELEGATION VAL_AC_BARE_RRSIG
	       VAL_AC_CAN_VERIFY VAL_AC_DATA_MISSING VAL_AC_DNSKEY_MISSING
	       VAL_AC_DNSKEY_NOMATCH VAL_AC_DNS_ERROR_BASE
	       VAL_AC_DNS_ERROR_LAST VAL_AC_DONT_VALIDATE VAL_AC_DS_MISSING
	       VAL_AC_ERROR_BASE VAL_AC_FAIL_BASE VAL_AC_IGNORE_VALIDATION
	       VAL_AC_INIT VAL_AC_INVALID_KEY VAL_AC_INVALID_RRSIG
	       VAL_AC_KEY_NOT_AUTHORIZED VAL_AC_KEY_TOO_LARGE
	       VAL_AC_KEY_TOO_SMALL VAL_AC_LAST_BAD VAL_AC_LAST_ERROR
	       VAL_AC_LAST_FAILURE VAL_AC_LAST_STATE VAL_AC_LOCAL_ANSWER
	       VAL_AC_NEGATIVE_PROOF VAL_AC_NOT_VERIFIED VAL_AC_NO_TRUST_ANCHOR
	       VAL_AC_PROVABLY_UNSECURE VAL_AC_RRSIG_ALGORITHM_MISMATCH
	       VAL_AC_RRSIG_EXPIRED VAL_AC_RRSIG_MISSING
	       VAL_AC_RRSIG_NOTYETACTIVE VAL_AC_RRSIG_VERIFIED
	       VAL_AC_RRSIG_VERIFY_FAILED VAL_AC_SIGNING_KEY VAL_AC_TRUST_KEY
	       VAL_AC_UNKNOWN_ALGORITHM VAL_AC_UNKNOWN_ALGORITHM_LINK
	       VAL_AC_UNKNOWN_DNSKEY_PROTOCOL VAL_AC_UNSET
	       VAL_AC_UNTRUSTED_ZONE VAL_AC_VERIFIED VAL_AC_VERIFIED_LINK
	       VAL_AC_WAIT_FOR_RRSIG VAL_AC_WAIT_FOR_TRUST
	       VAL_AC_WCARD_VERIFIED VAL_AC_WRONG_LABEL_COUNT VAL_BAD_ARGUMENT
	       VAL_BARE_RRSIG VAL_BOGUS VAL_CONF_NOT_FOUND VAL_CONF_PARSE_ERROR
	       VAL_CTX_IDLEN VAL_DNS_ERROR_BASE VAL_DNS_ERROR_LAST VAL_ERROR
	       VAL_FLAGS_DEFAULT VAL_FLAGS_DONT_VALIDATE VAL_FROM_ADDITIONAL
	       VAL_FROM_ANSWER VAL_FROM_AUTHORITY VAL_FROM_QUERY VAL_FROM_UNSET
	       VAL_IGNORE_VALIDATION VAL_INDETERMINATE VAL_INTERNAL_ERROR
	       VAL_LOCAL_ANSWER VAL_LOG_OPTIONS VAL_NONEXISTENT_NAME
	       VAL_NONEXISTENT_NAME_OPTOUT VAL_NONEXISTENT_TYPE VAL_NOTRUST
	       VAL_NOT_IMPLEMENTED VAL_NO_ERROR VAL_NO_PERMISSION VAL_NO_POLICY
	       VAL_OUT_OF_MEMORY VAL_PROVABLY_UNSECURE VAL_QUERY_MERGE_RRSETS
	       VAL_RESOURCE_UNAVAILABLE VAL_R_BOGUS VAL_R_BOGUS_PROOF
	       VAL_R_BOGUS_PROVABLE VAL_R_BOGUS_UNPROVABLE VAL_R_DONT_KNOW
	       VAL_R_IGNORE_VALIDATION VAL_R_INCOMPLETE_PROOF
	       VAL_R_INDETERMINATE VAL_R_INDETERMINATE_DS
	       VAL_R_INDETERMINATE_PROOF VAL_R_IRRELEVANT_PROOF VAL_R_LAST
	       VAL_R_MASKED_TRUST_FLAG VAL_R_PROVABLY_UNSECURE VAL_R_TRUST_FLAG
	       VAL_R_VALIDATED_CHAIN VAL_R_VERIFIED_CHAIN VAL_SUCCESS
	       ZONE_USE_NOTHING ZONE_USE_TSIG 
	      );

bootstrap Net::DNS::SEC::Validator;

sub new {       
    my $class = shift;
    my $self  = {};
    my %params = @_;

    @$self{keys %params} = values %params;
    
    $self->{_ctx_ptr} = 
	Net::DNS::SEC::Validator::_create_context($self->{policy});

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
	    Net::DNS::SEC::Validator::_switch_policy($ctx_ptr, $label);
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
	$self->{_ctx_ptr} = Net::DNS::SEC::Validator::_create_context($label);
	$self->{policy} = $label;    
    }
    return $self->{policy};
}

sub getaddrinfo
{
    my $self = shift;

    my $result = Net::DNS::SEC::Validator::_getaddrinfo($self->{_ctx_ptr},@_);
    
    if ($result =~ /^\d+$/) {
	$self->{Error} = $result;
	$self->{ErrorStr} = Net::DNS::SEC::Validator::_gai_strerror($result);
	$result = [];
    }

    return (ref $result eq 'ARRAY' ? @{$result} : ());
}

sub res_query {
    my $self = shift;
    my $ctx = $self->{_ctx_ptr};
    my $dname = shift;
    my $class = shift;
    my $type = shift;

    $class = Net::DNS::classesbyname($class) unless $class =~ /^\d+$/;
    $type = Net::DNS::typesbyname($type) unless $type =~ /^\d+$/;
    
    return Net::DNS::SEC::Validator::_res_query($ctx, $dname, $class, $type);
}

sub gethostbyname {
    my $self = shift;
    my $ctx = $self->{_ctx_ptr};
    my $name = shift;
    
    my $result = Net::DNS::SEC::Validator::_gethostbyname($ctx, $name);

    return $result;
}


sub DESTROY {
    my $self = shift;

}

1;
__END__

=head1 NAME

Net::addrinfo - interface to POSIX getaddrinfo(3) and related
constants, structures and functions.

=head1 SYNOPSIS

 use Net::addrinfo;
 my $ainfo = getaddrinfo("www.marzot.net");

=head1 DESCRIPTION

This module exports getaddrinfo() and related functions. Where
appropriate the functions return "Net::addrinfo" objects.  This object
has methods that return the similarly named structure field name from
the C's addrinfo structure from F<netdb.h>; namely (flags, family,
protocol, addrlen, addr, canonname).

You may also import all the structure fields directly into your namespace
as regular variables using the :FIELDS import tag.  (Note that this still
overrides your core functions.)  Access these fields as variables named
with a preceding C<h_>.  Thus, C<$host_obj-E<gt>name()> corresponds to
$h_name if you import the fields.  Array references are available as
regular array variables, so for example C<@{ $host_obj-E<gt>aliases()
}> would be simply @h_aliases.

The gethost() function is a simple front-end that forwards a numeric
argument to gethostbyaddr() by way of Socket::inet_aton, and the rest
to gethostbyname().

To access this functionality without the core overrides,
pass the C<use> an empty import list, and then access
function functions with their full qualified names.
On the other hand, the built-ins are still available
via the C<CORE::> pseudo-package.

=head1 EXAMPLES

 use Net::addrinfo;
 use Socket;

 @ARGV = ('netscape.com') unless @ARGV;

 for $host ( @ARGV ) {

    unless ($h = gethost($host)) {
	warn "$0: no such host: $host\n";
	next;
    }

    printf "\n%s is %s%s\n", 
	    $host, 
	    lc($h->name) eq lc($host) ? "" : "*really* ",
	    $h->name;

    print "\taliases are ", join(", ", @{$h->aliases}), "\n"
		if @{$h->aliases};     

    if ( @{$h->addr_list} > 1 ) { 
	my $i;
	for $addr ( @{$h->addr_list} ) {
	    printf "\taddr #%d is [%s]\n", $i++, inet_ntoa($addr);
	} 
    } else {
	printf "\taddress is [%s]\n", inet_ntoa($h->addr);
    } 

    if ($h = gethostbyaddr($h->addr)) {
	if (lc($h->name) ne lc($host)) {
	    printf "\tThat addr reverses to host %s!\n", $h->name;
	    $host = $h->name;
	    redo;
	} 
    }
 }

=head1 NOTE

While this class is currently implemented using the Class::Struct
module to build a struct-like class, you shouldn't rely upon this.

=head1 AUTHOR

G. S. Marzot
