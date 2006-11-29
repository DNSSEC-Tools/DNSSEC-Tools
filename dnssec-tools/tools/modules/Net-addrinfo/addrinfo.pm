#
#    addrinfo.pm -- Perl 5 interface to getaddrinfo(3) and related structs
#
#    written by G. S. Marzot (marz@users.sourceforge.net)
#
#    Copyright (c) 2006 G. S. Marzot. All rights reserved.
#
#    Copyright (c) 2006 SPARTA, Inc.  All rights reserved.
#
#    This program is free software; you can redistribute it and/or
#    modify it under the same terms as Perl itself.
#
package Net::addrinfo;
use Socket qw(:all);
use Carp;

our $VERSION = '0.10a';   # current release version number

use Exporter;
use DynaLoader;

sub AUTOLOAD {
    my $sub = $AUTOLOAD;
    (my $constname = $sub) =~ s/.*:://;

    my $val = (exists $LOCAL_CONSTANTS{$constname} ? 
	       $LOCAL_CONSTANTS{$constname} : constant($constname));
    if (not defined $val) {
	croak "Your vendor has not defined constant $constname";
    }
    *$sub = sub { $val }; # same as: eval "sub $sub { $val }";
    goto &$sub;
}

our @ISA = qw(Exporter DynaLoader);

# our @EXPORT = qw( getaddrinfo );

our @AI_FLAGS = qw(AI_NUMERICHOST AI_NUMERICSERV AI_PASSIVE AI_V4MAPPED AI_ADDRCONFIG AI_ALL AI_CANONIDN AI_CANONNAME AI_IDN AI_IDN_ALLOW_UNASSIGNED AI_IDN_USE_STD3_ASCII_RULES);

#hack to make up for missing constants - should be provided with 'Socket'
our %LOCAL_CONSTANTS = qw(IPPROTO_IP 0 IPPROTO_HOPOPTS 0 IPPROTO_ICMP 1 IPPROTO_IGMP 2 IPPROTO_IPIP 4 IPPROTO_EGP 8 IPPROTO_PUP 12 IPPROTO_UDP 17 IPPROTO_IDP 22 IPPROTO_TP 29 IPPROTO_IPV6 41 IPPROTO_ROUTING 43 IPPROTO_FRAGMENT 44 IPPROTO_RSVP 46 IPPROTO_GRE 47 IPPROTO_ESP 50 IPPROTO_AH 51 IPPROTO_ICMPV6 58 IPPROTO_NONE 59 IPPROTO_RAW 255 IPPROTO_DSTOPTS 60 IPPROTO_MTP 92 IPPROTO_ENCAP 98 IPPROTO_PIM 103 IPPROTO_COMP 108 IPPROTO_SCTP 132);

our @EXPORT = qw(getaddrinfo gai_strerror AI_ADDRCONFIG AI_ALL AI_CANONIDN AI_CANONNAME AI_IDN AI_IDN_ALLOW_UNASSIGNED AI_IDN_USE_STD3_ASCII_RULES AI_NUMERICHOST AI_NUMERICSERV AI_PASSIVE AI_V4MAPPED EAI_ADDRFAMILY EAI_AGAIN EAI_ALLDONE EAI_BADFLAGS EAI_CANCELED EAI_FAIL EAI_FAMILY EAI_IDN_ENCODE EAI_INPROGRESS EAI_INTR EAI_MEMORY EAI_NODATA EAI_NONAME EAI_NOTCANCELED EAI_OVERFLOW EAI_SERVICE EAI_SOCKTYPE EAI_SYSTEM GAI_NOWAIT GAI_WAIT NI_DGRAM NI_IDN NI_IDN_ALLOW_UNASSIGNED NI_IDN_USE_STD3_ASCII_RULES NI_MAXHOST NI_MAXSERV NI_NAMEREQD NI_NOFQDN NI_NUMERICHOST NI_NUMERICSERV IPPROTO_IP IPPROTO_HOPOPTS IPPROTO_ICMP IPPROTO_IGMP IPPROTO_IPIP IPPROTO_EGP IPPROTO_PUP IPPROTO_UDP IPPROTO_IDP IPPROTO_TP IPPROTO_IPV6 IPPROTO_ROUTING IPPROTO_FRAGMENT IPPROTO_RSVP IPPROTO_GRE IPPROTO_ESP IPPROTO_AH IPPROTO_ICMPV6 IPPROTO_NONE IPPROTO_RAW IPPROTO_DSTOPTS IPPROTO_MTP IPPROTO_ENCAP IPPROTO_PIM IPPROTO_COMP IPPROTO_SCTP);

bootstrap Net::addrinfo;

sub new {
    my $type = shift;
    my $self = {flags=>0, family=>0, socktype=>0, protocol=>0, 
		addr=>undef, cannonname=>undef};
    my %params = @_;
    @$self{keys %params} = values %params;

    bless $self, $type;
}

sub flags {
    my $self = shift;

    if (@_) {
	$self->{flags} = scalar(shift);
    }
    return $self->{flags};
}

sub family {
    my $self = shift;

    if (@_) {
	$self->{family} = int(shift);
    }
    return $self->{family};
}

sub socktype {
    my $self = shift;

    if (@_) {
	$self->{socktype} = int(shift);
    }
    return $self->{socktype};
}

sub protocol {
    my $self = shift;

    if (@_) {
	$self->{protocol} = int(shift);
    }
    return $self->{protocol};
}

sub addr {
    my $self = shift;

    if (@_) {
	$self->{addr} = scalar(shift);
    }
    return $self->{addr};
}

sub canonname {
    my $self = shift;

    if (@_) {
	$self->{canonname} = scalar(shift);
    }
    return $self->{canonname};
}

# special accessor sub for val_addrinfo structures in support of DNSSEC
# note: not present ot relevant for non-DNSSEC applications
sub val_status {
    my $self = shift;

    if (@_) {
	$self->{val_status} = scalar(shift);
    }
    return $self->{val_status};
}

sub stringify {
    my $self = shift;
    my $dstr;

    $dstr .= "{\n";
    my $flags = join('|',grep {$self->flags & eval("\&$_;");}@AI_FLAGS);
    $dstr .= "\tai_flags = ($flags)\n";
    my $family = $self->family;
    $family = (($family == AF_UNSPEC) ? "AF_UNSPEC" : 
	       (($family == AF_INET) ? "AF_INET" : 
		(($family == AF_INET6) ? "AF_INET6" : "Unknown")));
    $dstr .= "\tai_family = $family\n"; 
    my $socktype =  $self->socktype;
    $socktype = (($socktype == SOCK_STREAM) ? "SOCK_STREAM" :
		 (($socktype == SOCK_DGRAM) ? "SOCK_DGRAM" :
		  (($socktype == SOCK_RAW) ? "SOCK_RAW" : "Unknown")));
    $dstr .= "\tai_socktype = $socktype\n"; 
    my $protocol = $self->protocol;

    $protocol = (($protocol == IPPROTO_UDP()) ? "IPPROTO_UDP" :
		 (($protocol == IPPROTO_TCP) ? "IPPROTO_TCP" :
		  (($protocol == IPPROTO_IP()) ? "IPPROTO_IP" : "Unknown")));
    $dstr .= "\tai_protocol = $protocol\n";
    my $addrlen = length($self->addr);
    $dstr .= "\tai_addrlen = $addrlen\n";
    my $addr;
    if ($self->addr) {
	if ($self->family == AF_INET) { 
	    my ($port,$iaddr) = unpack_sockaddr_in($self->addr);
	    $addr = "($port, " . inet_ntoa($iaddr) . ")";
#	} elsif ($self->family == AF_INET6) {
#	    
	} else {
	    $addr = "0x" . unpack("H*",$self->addr);
	}
    }
    $dstr .= "\tai_addr = $addr\n";
    my $canonname = (defined $self->canonname ? $self->canonname : "<undef>");
    $dstr .= "\tai_canonname = $canonname\n";
    if (exists $self->{val_status}) {
	my $val_status = $self->val_status;
	$dstr .= "\tai_canonname = $val_status\n";
    }
    $dstr .= "}\n";
    
    return $dstr;
}


sub getaddrinfo { 
    my $addrinfo = Net::addrinfo::_getaddrinfo(@_); 

    return $addrinfo;
} 

sub gai_strerror {
    my $errstr = Net::addrinfo::_gai_strerror(@_);

    return $errstr;
}

sub DESTROY {
#    print STDERR "addrinfo:DESTROY\n";
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
