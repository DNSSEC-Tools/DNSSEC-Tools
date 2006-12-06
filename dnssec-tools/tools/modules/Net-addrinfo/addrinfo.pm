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

our $VERSION = '1.0b1';   # current release version number

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
    my $self = {flags=>0, family=>0, socktype=>0, protocol=>0, addrlen=>0,
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

sub addrlen {
    my $self = shift;

    if (@_) {
	$self->{addrlen} = int(shift);
    }

    return $self->{addrlen};
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
    my $addrlen = $self->addrlen || length($self->addr);
    $dstr .= "\tai_addrlen = $addrlen\n";
    my $addr;
    if ($self->addr) {
	if ($self->family == AF_INET) { 
	    my ($port,$iaddr) = unpack_sockaddr_in($self->addr);
	    $addr = "($port, " . inet_ntoa($iaddr) . ")";
#	} elsif ($self->family == AF_INET6) {
#	    
# XXX needs implementation
	} else {
	    $addr = "0x" . unpack("H*",$self->addr);
	}
    }
    $dstr .= "\tai_addr = $addr\n";
    my $canonname = (defined $self->canonname ? $self->canonname : "<undef>");
    $dstr .= "\tai_canonname = $canonname\n";
    if (exists $self->{val_status}) {
	my $val_status = $self->val_status;
	$dstr .= "\tai_val_status = $val_status\n";
    }
    $dstr .= "}\n";
    
    return $dstr;
}


sub getaddrinfo { 
    my $result = Net::addrinfo::_getaddrinfo(@_); 
    
    $result = [$result] unless ref $result eq 'ARRAY';
    
    return (wantarray ? @$result : shift(@$result)); 
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

This Perl module is designed to implement and export functionality
related to the POSIX getaddrinfo(3) system call. The Net::addrinfo
data object is provided with field name accsessor functions, similarly
named to the the C data structure definition in F<netdb.h>;. The
getaddrinfo(3), gai_strerror(3) calls, and related constants are
exported.

The getaddrinfo() routine mimics the POSIX documented funtion (see
system man page getaddrinfo(3)). 

On success the getaddrinfo() function will return an array of
Net::addrinfo data objects, or a numeric error code.

In scalar context getaddrinfo() will return the first element from the
Net::addrinfo array or the error code: 

The error code may be passed to gai_strerror() to get a string
representation of the error.

New Net::addrinfo objects may be created with the package constructor
and any number (or none) of the fields may be specified. 

   flags => scalar integer
   family => scalar integer (e.g., AF_INET,m AF_INET6, etc.)
   socktype => scalar integer (e.g., SOCK_DGRAM, SOCK_STREAM, etc.)
   protocol => scalar integer (e.g., IPPROTO_UDP, IPPROTO_TCP, etc.)
   addrlen => scalar integer (can be computed by length($self->addr))
   addr => packed bytes (e.g., $self->addr(inet_aton("192.168.1.1")); )

Flags may be set in the structure so that it may be used as a 'hint'
parameter to the getaddrinfo() function. See exported @AI_FLAGS for
list of acceptable constants.

(Note: a special scalar integer field, 'val_status', is provided in
support of DNSSEC aware addrinfo results (see Net::DNS::SEC::Valaidator))


=head1 EXAMPLES

 use Net::addrinfo;
 use Socket;

   use Socket qw(:all);
   my $hint = new Net::addrinfo(flags => AI_CANONNAME,
                                family => AF_INET, 
                                socktype => SOCK_DGRAM);

   my (@ainfo) = getaddrinfo("www.marzot.net", "http", $hint);

   foreach $ainfo (@ainfo) {
      if (ref $ainfo eq 'Net::addrinfo') {
	print $ainfo->stringify(), "\n";
	print "addr = ", inet_ntoa($ainfo->addr), "\n";
	...
        connect(SH, $ainfo->addr);
      } else {
         print "Error($ainfo):", gai_strerror($ainfo), "\n";
      }
   }

=head1 NOTE

One should not rely on the internal representation of this class.

=head1 AUTHOR

G. S. Marzot (marz@users.sourceforge.net)
