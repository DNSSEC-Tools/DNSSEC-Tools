# ----------------------------------------------------------------------------
# "THE BEER-WARE LICENSE" (Revision 42)
# <tobez@tobez.org> wrote this file.  As long as you retain this notice you
# can do whatever you want with this stuff. If we meet some day, and you think
# this stuff is worth it, you can buy me a beer in return.   Anton Berezin
# ----------------------------------------------------------------------------
#
# $Id$
#
package Net::DNS::ZoneFile::Fast;
# documentation at the __END__ of the file

use strict;
use 5.005;
use vars qw($VERSION);
use IO::File;
use Net::DNS;

$VERSION = '0.5';

my $MAXIMUM_TTL = 0x7fffffff;

my $pat_ttl = qr{[\dwdhms]+}i;
my $pat_skip = qr{\s*(?:;.*)?};
my $pat_name = qr{[-\w\$\d*]+(?:\.[-\w\$\d]+)*};
my $pat_maybefullname = qr{[-\w\$\d*]+(?:\.[-\w\$\d]+)*\.?};

my $debug;
my $domain;
my $parse;
my $ln;
my $default_ttl;
my $minimum;
my $origin;
my $ttl;
my @zone;
my $soa;
my $on_error;
my $quiet;
my $soft_errors;

sub parse
{
	my %param;
	my $text;

	$on_error = undef;
	$parse = \&parse_line;
	$ln = 0;
	$domain = ".";
	$default_ttl = -1;
	$minimum = -1;
	@zone = ();

	if (@_ == 1) {
		$text = shift;
	} else {
		%param = @_;
		if (defined $param{text}) {
			$text = $param{text};
		} elsif (defined $param{fh}) {
		} elsif (defined $param{file}) {
			$param{fh} = IO::File->new($param{file}, "r");
			error("cannot open $param{file}: $!") unless defined $param{fh};
		} else {
			error("want zone text, or file, or fh");
		}
	}

	$debug = $param{debug};
	$quiet = $param{quiet};
	$origin = $param{origin};
	$origin = "." unless defined $origin;
	$origin = ".$origin" unless $origin =~ /^\./;
	$origin = "$origin." unless $origin =~ /\.$/;
	$on_error = $param{on_error} || undef;
	$param{soft_errors} = 1 if $on_error && !exists $param{soft_errors};
	$quiet = 1 if $on_error && !exists $param{quiet};
	$soft_errors = $param{soft_errors};

	eval {
		if ($param{fh}) {
			my $fh = $param{fh};
			while ($_ = readline($fh)) {
				$ln++;
				$parse->();
			}
		} else {
			my @text = split "\n", $text;
			for (@text) {
				$ln++;
				$parse->();
			}
		}
	};
	if ($@) {
		return undef if $param{soft_errors};
		die;
	}

	my @r;
	$minimum = 0 if $minimum < 0;
	for my $z (@zone) {
		$z->{ttl} = $minimum if $z->{ttl} <= 0;
		chop $z->{name};
		my $line = $z->{Line};
		my $lines = $z->{Lines} || 1;
		delete $z->{Line};
		delete $z->{Lines};
		if ($param{tolower}) {
			$z->{name} = lc $z->{name};
			$z->{cname} = lc $z->{cname} if defined $z->{cname};
			$z->{exchange} = lc $z->{exchange} if defined $z->{exchange};
			$z->{mname} = lc $z->{mname} if defined $z->{mname};
			$z->{rname} = lc $z->{rname} if defined $z->{rname};
			$z->{nsdname} = lc $z->{nsdname} if defined $z->{nsdname};
			$z->{ptrdname} = lc $z->{ptrdname} if defined $z->{ptrdname};
			$z->{target} = lc $z->{target} if defined $z->{target};
			$z->{mbox} = lc $z->{mbox} if defined $z->{mbox};
			$z->{txtdname} = lc $z->{txtdname} if defined $z->{txtdname};
		} elsif ($param{toupper}) {
			$z->{name} = uc $z->{name};
			$z->{cname} = uc $z->{cname} if defined $z->{cname};
			$z->{exchange} = uc $z->{exchange} if defined $z->{exchange};
			$z->{mname} = uc $z->{mname} if defined $z->{mname};
			$z->{rname} = uc $z->{rname} if defined $z->{rname};
			$z->{nsdname} = uc $z->{nsdname} if defined $z->{nsdname};
			$z->{ptrdname} = uc $z->{ptrdname} if defined $z->{ptrdname};
			$z->{target} = uc $z->{target} if defined $z->{target};
			$z->{mbox} = uc $z->{mbox} if defined $z->{mbox};
			$z->{txtdname} = uc $z->{txtdname} if defined $z->{txtdname};
		}
		push @r, Net::DNS::RR->new_from_hash(%$z);
		$r[-1]->{Line} = $line;
		$r[-1]->{Lines} = $lines;
	}
	return \@r;
}

sub error
{
	if ($on_error) {
		$on_error->($ln, @_);
	} else {
		warn "@_, line $ln\n" if $soft_errors && !$quiet;
	}
	die "@_, line $ln\n";
}

sub parse_line
{
	if (/^\$include\b/ig) {
		error("include niy");
		return;
	} elsif (/^\$origin[ \t]+/ig) {
		if (/\G($pat_maybefullname)$pat_skip$/gc) {
			my $name = $1;
			$name = "$name$origin" unless $name =~ /\.$/;
			$origin = $name;
			$origin = ".$origin" unless $origin =~ /^\./;
			return;
		} elsif (/\G\.$pat_skip$/gc) {
			$origin = ".";
			return;
		} else {
			error("bad \$ORIGIN");
		}
	} elsif (/^\$generate[ \t]+/ig) {
		if (/\G(\d+)\s*-\s*(\d+)\s+(.*)$/) {
			my $from = $1;
			my $to = $2;
			my $pat = $3;
			error("bad range in \$GENERATE") if $from > $to;
			error("\$GENERATE pattern without a wildcard") if $pat !~ /\$/;
			while ($from <= $to) {
				$_ = $pat;
				s/\$/$from/g;
				$parse->();
				$from++;
			}
			return;
		} else {
			error("bad \$GENERATE");
		}
	} elsif (/^\$ttl\b/ig) {
		if (/\G\s+($pat_ttl)$pat_skip$/) {
			my $v = $1;
			$ttl = $default_ttl = ttl_fromtext($v);
			if ($default_ttl <= 0 || $default_ttl > $MAXIMUM_TTL) {
				error("bad TTL value `$v'");
			} else {
				debug("\$TTL <= $default_ttl\n") if $debug;
			}
		} else {
			error("wrong \$TTL");
		}
		return;
	} elsif (/^$pat_skip$/g) {
		# skip
		return;
	} elsif (/^[ \t]+/g) {
		# fall through
	} elsif (/^\.[ \t]+/g) {
		$domain = ".";
	} elsif (/^\@[ \t]+/g) {
		$domain = $origin;
		$domain =~ s/^.// unless $domain eq ".";
	} elsif (/^$/g) {
		# skip
		return;
	} elsif (/^($pat_name\.)[ \t]+/g) {
		$domain = $1;
	} elsif (/^($pat_name)[ \t]+/g) {
		$domain = "$1$origin";
	} else {
		error("syntax error");
	}
	if (/\G($pat_ttl)[ \t]+/gc) {
		my $v = $1;
		$ttl = ttl_fromtext($v);
		if ($ttl == 0) {
			$ttl = $default_ttl;
		} else {
			if ($ttl <= 0 || $ttl > $MAXIMUM_TTL) {
				error("bad TTL value `$v'");
			}
		}
	} else {
		$ttl = $default_ttl;
	}
	if (/\G(in)[ \t]+/igc) {
		# skip; we only support IN class
	}
	if (/\G(a)[ \t]+/igc) {
		if (/\G(\d+)\.(\d+)\.(\d+)\.(\d+)$pat_skip$/ &&
			$1 < 256 && $2 < 256  && $3 < 256 && $4 < 256)
		{
			push @zone, {
				Line    => $ln,
				name    => $domain,
				type    => "A",
				ttl     => $ttl,
				class   => "IN",
				address => "$1.$2.$3.$4",
			};
		} else {
			error("bad IP address");
		}
	} elsif (/\G(ptr)[ \t]+/igc) {
		if (/\G($pat_maybefullname)$pat_skip$/gc) {
			my $name = $1;
			$name = "$name$origin" unless $name =~ /\.$/;
			chop $name;
			push @zone, {
				Line     => $ln,
				name     => $domain,
				type     => "PTR",
				ttl      => $ttl,
				class    => "IN",
				ptrdname => $name,
			};
		} elsif (/\G\@$pat_skip$/gc) {
			my $name = $origin;
			$name =~ s/^.// unless $name eq ".";
			chop $name;
			push @zone, {
				Line     => $ln,
				name     => $domain,
				type     => "PTR",
				ttl      => $ttl,
				class    => "IN",
				ptrdname => $name,
			};
		} else {
			error("bad name in PTR");
		}
	} elsif (/\G(cname)[ \t]+/igc) {
		if (/\G($pat_maybefullname)$pat_skip$/gc) {
			my $name = $1;
			$name = "$name$origin" unless $name =~ /\.$/;
			chop $name;
			push @zone, {
				Line  => $ln,
				name  => $domain,
				type  => "CNAME",
				ttl   => $ttl,
				class => "IN",
				cname => $name,
			};
		} elsif (/\G\@$pat_skip$/gc) {
			my $name = $origin;
			$name =~ s/^.// unless $name eq ".";
			chop $name;
			push @zone, {
				Line     => $ln,
				name     => $domain,
				type     => "CNAME",
				ttl      => $ttl,
				class    => "IN",
				cname    => $name,
			};
		} else {
			error("bad cname in CNAME");
		}
	} elsif (/\G(mx)[ \t]+/igc) {
		my $prio;
		if (/\G(\d+)[ \t]+/gc) {
			$prio = $1;
		} else {
			error("bad priority in MX");
		}
		if (/\G($pat_maybefullname)$pat_skip$/gc) {
			my $name = $1;
			$name = "$name$origin" unless $name =~ /\.$/;
			chop $name;
			push @zone, {
				Line       => $ln,
				name       => $domain,
				type       => "MX",
				ttl        => $ttl,
				class      => "IN",
				preference => $prio,
				exchange   => $name,
			};
		} elsif (/\G\@$pat_skip$/gc) {
			my $name = $origin;
			$name =~ s/^.// unless $name eq ".";
			chop $name;
			push @zone, {
				Line       => $ln,
				name       => $domain,
				type       => "MX",
				ttl        => $ttl,
				class      => "IN",
				preference => $prio,
				exchange   => $name,
			};
		} else {
			error("bad exchange in CNAME");
		}
	} elsif (/\G(aaaa)[ \t]+/igc) {
		if (/\G([\da-fA-F:.]+)$pat_skip$/) {
			# parsing stolen from Net::DNS::RR::AAAA
			my $string = $1;
			if ($string =~ /^(.*):(\d+)\.(\d+)\.(\d+)\.(\d+)$/) {
				my ($front, $a, $b, $c, $d) = ($1, $2, $3, $4, $5);
				$string = $front . sprintf(":%x:%x",
										   ($a << 8 | $b),
										   ($c << 8 | $d));
			}

			my @addr;
			if ($string =~ /^(.*)::(.*)$/) {
				my ($front, $back) = ($1, $2);
				my @front = split(/:/, $front);
				my @back  = split(/:/, $back);
				my $fill = 8 - (@front ? $#front + 1 : 0)
					- (@back  ? $#back  + 1 : 0);
				my @middle = (0) x $fill;
				@addr = (@front, @middle, @back);
			} else {
				@addr = split(/:/, $string);
				if (@addr < 8) {
					@addr = ((0) x (8 - @addr), @addr);
				}
			}

			push @zone, {
				Line    => $ln,
				name    => $domain,
				type    => "AAAA",
				ttl     => $ttl,
				class   => "IN",
				address => sprintf("%x:%x:%x:%x:%x:%x:%x:%x",
								   map { hex $_ } @addr),
			};
		} else {
			error("bad IPv6 address");
		}
	} elsif (/\G(ns)[ \t]+/igc) {
		if (/\G($pat_maybefullname)$pat_skip$/gc) {
			my $name = $1;
			$name = "$name$origin" unless $name =~ /\.$/;
			chop $name;
			push @zone, {
				Line    => $ln,
				name    => $domain,
				type    => "NS",
				ttl     => $ttl,
				class   => "IN",
				nsdname => $name,
			};
		} elsif (/\G\@$pat_skip$/gc) {
			my $name = $origin;
			$name =~ s/^.// unless $name eq ".";
			chop $name;
			push @zone, {
				Line    => $ln,
				name    => $domain,
				type    => "NS",
				ttl     => $ttl,
				class   => "IN",
				nsdname => $name,
			};
		} else {
			error("bad name in NS");
		}
	} elsif (/\G(soa)\b/igc) {
		$parse = \&parse_soa_name;
		$soa = {
			Line      => $ln,
			name      => $domain,
			type      => "SOA",
			ttl       => $ttl,
			class     => "IN",
			breakable => 0,
			nextkey   => "mname",
		};
		$parse->();
		return;
	} elsif (/\G(txt)[ \t]+/igc) {
		if (/\G(["']?.*?["']?)$pat_skip$/gc) {
			push @zone, {
				Line    => $ln,
				name    => $domain,
				type    => "TXT",
				ttl     => $ttl,
				class   => "IN",
				txtdata => $1,
			};
		} else {
			error("bad txtdata in TXT");
		}
	} elsif (/\G(loc)[ \t]+/igc) {
		# parsing stolen from Net::DNS::RR::LOC
		if (/\G (\d+) \s+		# deg lat
			((\d+) \s+)?		# min lat
			(([\d.]+) \s+)?		# sec lat
			(N|S) \s+			# hem lat
			(\d+) \s+			# deg lon
			((\d+) \s+)?		# min lon
			(([\d.]+) \s+)?		# sec lon
			(E|W) \s+			# hem lon
			(-?[\d.]+) m? 		# altitude
			(\s+ ([\d.]+) m?)?	# size
			(\s+ ([\d.]+) m?)?	# horiz precision
			(\s+ ([\d.]+) m?)? 	# vert precision
			$pat_skip
			$/ixgc)
		{
			# Defaults (from RFC 1876, Section 3).
			my $default_min       = 0;
			my $default_sec       = 0;
			my $default_size      = 1;
			my $default_horiz_pre = 10_000;
			my $default_vert_pre  = 10;

			# Reference altitude in centimeters (see RFC 1876).
			my $reference_alt = 100_000 * 100;

			my $version = 0;

			my ($latdeg, $latmin, $latsec, $lathem) = ($1, $3, $5, $6);
			my ($londeg, $lonmin, $lonsec, $lonhem) = ($7, $9, $11, $12);
			my ($alt, $size, $horiz_pre, $vert_pre) = ($13, $15, $17, $19);

			$latmin    = $default_min       unless $latmin;
			$latsec    = $default_sec       unless $latsec;
			$lathem    = uc($lathem);

			$lonmin    = $default_min       unless $lonmin;
			$lonsec    = $default_sec       unless $lonsec;
			$lonhem    = uc($lonhem);

			$size      = $default_size      unless $size;
			$horiz_pre = $default_horiz_pre unless $horiz_pre;
			$vert_pre  = $default_vert_pre  unless $vert_pre;

			push @zone, {
				Line      => $ln,
				name      => $domain,
				type      => "LOC",
				ttl       => $ttl,
				class     => "IN",
				version   => $version,
				size      => $size * 100,
				horiz_pre => $horiz_pre * 100,
				vert_pre  => $vert_pre * 100,
				latitude  => dms2latlon($latdeg, $latmin, $latsec, $lathem),
				longitude => dms2latlon($londeg, $lonmin, $lonsec, $lonhem),
				altitude  => $alt * 100 + $reference_alt,
			};
		} else {
			error("bad LOC data");
		}
	} elsif (/\G(hinfo)[ \t]+/igc) {
		# parsing stolen from Net::DNS::RR::HINFO
		if (/\G["'](.*?)["']\s+["'](.*?)["']$pat_skip$/gc) {
			push @zone, {
				Line      => $ln,
				name      => $domain,
				type      => "HINFO",
				ttl       => $ttl,
				class     => "IN",
				cpu       => $1,
				os        => $2,
			};
		} else {
			error("bad HINFO data");
		}
	} elsif (/\G(srv)[ \t]+/igc) {
		# parsing stolen from Net::DNS::RR::SRV
		if (/\G(\d+)\s+(\d+)\s+(\d+)\s+(\S+)$pat_skip$/gc) {
			push @zone, {
				Line      => $ln,
				name      => $domain,
				type      => "SRV",
				ttl       => $ttl,
				class     => "IN",
				priority  => $1,
				weight    => $2,
				port      => $3,
				target    => $4,
			};
			$zone[-1]->{target} =~ s/\.+$//;
		} else {
			error("bad SRV data");
		}
	} elsif (/\G(rp)[ \t]+/igc) {
		my $mbox;
		if (/\G($pat_maybefullname)[ \t]+/gc) {
			$mbox = $1;
			$mbox = "$mbox$origin" unless $mbox =~ /\.$/;
			chop $mbox;
		} elsif (/\G\@[ \t]+/gc) {
			$mbox = $origin;
			$mbox =~ s/^.// unless $mbox eq ".";
			chop $mbox;
		} else {
			error("bad mbox in PTR");
		}

		my $txtdname;
		if (/\G($pat_maybefullname)$pat_skip$/gc) {
			$txtdname = $1;
			$txtdname = "$txtdname$origin" unless $txtdname =~ /\.$/;
			chop $txtdname;
		} elsif (/\G\@$pat_skip$/gc) {
			$txtdname = $origin;
			$txtdname =~ s/^.// unless $txtdname eq ".";
			chop $txtdname;
		} else {
			error("bad txtdname in PTR");
		}

		push @zone, {
			Line     => $ln,
			name     => $domain,
			type     => "RP",
			ttl      => $ttl,
			class    => "IN",
			mbox     => $mbox,
			txtdname => $txtdname,
		};
	} else {
		error("unrecognized type");
	}
}

# Reference lat/lon (see RFC 1876).
my $reference_latlon = 2**31;
# Conversions to/from thousandths of a degree.
my $conv_sec = 1000;
my $conv_min = 60 * $conv_sec;
my $conv_deg = 60 * $conv_min;

sub dms2latlon {
	my ($deg, $min, $sec, $hem) = @_;
	my ($retval);

	$retval = ($deg * $conv_deg) + ($min * $conv_min) + ($sec * $conv_sec);
	$retval = -$retval if ($hem eq "S") || ($hem eq "W");
	$retval += $reference_latlon;
	return $retval;
}

sub parse_soa_name
{
	error("parse_soa_name: internal error, no \$soa") unless $soa;
	if ($soa->{breakable}) {
		if (/\G[ \t]*($pat_maybefullname)$pat_skip$/igc) {
			$soa->{$soa->{nextkey}} = $1;
		} elsif (/\G$pat_skip$/gc) {
			return;
		} elsif (/\G[ \t]*($pat_name\.)[ \t]/igc) {
			$soa->{$soa->{nextkey}} = $1;
		} else {
			error("expected valid $soa->{nextkey}");
		}
	} else {
		if (/\G[ \t]+($pat_maybefullname)/igc) {
			$soa->{$soa->{nextkey}} = $1;
		} elsif (/\G[ \t]*\($pat_skip$/igc) {
			$soa->{breakable} = 1;
			return;
		} elsif (/\G[ \t]*\(/igc) {
			$soa->{breakable} = 1;
			$parse->();
			return;
		} else {
			error("expected valid $soa->{nextkey}");
		}
	}
	if ($soa->{nextkey} eq "mname") {
		$soa->{nextkey} = "rname";
	} elsif ($soa->{nextkey} eq "rname") {
		$soa->{nextkey} = "serial";
		$parse = \&parse_soa_number;
	} else {
		error("parse_soa_name: internal error, bad {nextkey}") unless $soa;
	}
	$parse->();
}

sub ttl_or_serial
{
	my ($v) = @_;
	if ($soa->{nextkey} eq "serial") {
		error("bad serial number") unless $v =~ /^\d+$/;
	} else {
		$v = ttl_fromtext($v);
		error("bad $soa->{nextkey}") unless $v;
	}
	return $v;
}

sub parse_soa_number
{
	error("parse_soa_number: internal error, no \$soa") unless $soa;
	if ($soa->{breakable}) {
		if (/\G[ \t]*($pat_ttl)$pat_skip$/igc) {
			$soa->{$soa->{nextkey}} = ttl_or_serial($1);
		} elsif (/\G$pat_skip$/gc) {
			return;
		} elsif (/\G[ \t]*($pat_ttl)\b/igc) {
			$soa->{$soa->{nextkey}} = ttl_or_serial($1);
		} else {
			error("expected valid $soa->{nextkey}");
		}
	} else {
		if (/\G[ \t]+($pat_ttl)/igc) {
			$soa->{$soa->{nextkey}} = ttl_or_serial($1);
		} elsif (/\G[ \t]*\($pat_skip$/igc) {
			$soa->{breakable} = 1;
			return;
		} elsif (/\G[ \t]*\(/igc) {
			$soa->{breakable} = 1;
			$parse->();
			return;
		} else {
			error("expected valid $soa->{nextkey}");
		}
	}
	if ($soa->{nextkey} eq "serial") {
		$soa->{nextkey} = "refresh";
	} elsif ($soa->{nextkey} eq "refresh") {
		$soa->{nextkey} = "retry";
	} elsif ($soa->{nextkey} eq "retry") {
		$soa->{nextkey} = "expire";
	} elsif ($soa->{nextkey} eq "expire") {
		$soa->{nextkey} = "minimum";
	} elsif ($soa->{nextkey} eq "minimum") {
		$minimum = $soa->{minimum};
		$default_ttl = $minimum if $default_ttl <= 0;
		$parse = $soa->{breakable} ? \&parse_close : \&parse_line;
		if (!$soa->{breakable} && !/\G$pat_skip$/gc) {
			error("unexpected trailing garbage after Minimum");
		}
		delete $soa->{nextkey};
		delete $soa->{breakable};
		chop $soa->{mname};
		chop $soa->{rname};
		$soa->{Lines} = $ln - $soa->{Line} + 1;
		push @zone, $soa;
		$soa = undef;
		return if $parse == \&parse_line;
	} else {
		error("parse_soa_number: internal error, bad {nextkey}") unless $soa;
	}
	$parse->();
}

sub parse_close
{
	if (/\G[ \t]*\)$pat_skip$/igc) {
		$zone[-1]->{Lines} = $ln - $zone[-1]->{Line} + 1;
		$parse = \&parse_line;
		return;
	} elsif (/\G$pat_skip$/gc) {
		return;
	} else {
		error("expected closing block \")\"");
	}
}

sub debug
{
	print STDERR @_;
}

sub ttl_fromtext
# zero == invalid value
{
	my ($t) = @_;
	my $ttl = 0;
	if ($t =~ /^\d+$/) {
		$ttl = $t;
	} elsif ($t =~ /^(?:\d+[WDHMS])+$/i) {
		my %ttl;
		$ttl{W} ||= 0;
		$ttl{D} ||= 0;
		$ttl{H} ||= 0;
		$ttl{M} ||= 0;
		$ttl{S} ||= 0;
		while ($t =~ /(\d+)([WDHMS])/gi) {
			$ttl{uc($2)} += $1;
		}
		$ttl = $ttl{S} + 60*($ttl{M} + 60*($ttl{H} + 24*($ttl{D} + 7*$ttl{W})));
	}
	return $ttl;
}

1;

__END__

=head1 NAME

Net::DNS::ZoneFile::Fast -- parse BIND8/9 zone files

=head1 SYNOPSIS

  use Net::DNS::ZoneFile::Fast;

  my $rr = Net::DNS::ZoneFile::Fast::parse($zone_text);

=head1 DESCRIPTION

The Net::DNS::ZoneFile::Fast module provides an ability to parse zone
files that BIND8 and BIND9 use, fast.  Currently it provides a single
function, I<parse()>, which returns a reference to an array of
traditional I<Net::DNS::RR> objects, so that no new API has to be
learned in order to manipulate zone records.

Great care was taken to ensure that I<parse()> does its job as fast as
possible, so it is interesting to use this module to parse huge zones.
As an example datapoint, it takes less than 5 seconds to parse a 2.2 MB
zone with about 72000 records on an Athlon XP 2600+ box.

On the other hand, it is likely that I<Net::DNS::RR> objects that
I<parse()> returns are going to be further processed.  To make it easier
to link any record back to the zone file (say, to report a logical error
like infamous `CNAME and other data' back to the user, or to do a zone
file modification), I<parse()> inserts line numbering information into
I<Net::DNS::RR> objects.

The module currently understands:

=over 4

=item B<$GENERATE> directive

=item B<$ORIGIN> directive

=item B<$TTL> directive

=item B<A> records

=item B<AAAA> records

=item B<CNAME> records

=item B<HINFO> records

=item B<LOC> records

=item B<MX> records

=item B<NS> records

=item B<PTR> records

=item B<RP> records

=item B<SOA> records

=item B<SRV> records

=item B<TXT> records

=back

=head2 Non-standard third-party modules

I<Net::DNS>.

=head2 Exports

None.

=head2 Subroutines

=over 4

=item I<parse>

Parses zone data and returns a reference to an array of I<Net::DNS::RR>
objects if successful.  Takes the following named (no pun intended)
parameters:

=over 4

=item B<text>

A semi-mandatory parameter, textual contents of the zone to be parsed.

=item B<fh>

A semi-mandatory parameter, a file handle from which zone contents can
be read for parsing.

=item B<file>

A semi-mandatory parameter, a file name with the zone to parse.

=item B<origin>

An optional parameter specifying zone origin.  The default is ".".  A
trailing "." is appended if necessary.

=item B<on_error>

An optional parameter, user-defined error handler.  If specified, it
must be a subroutine reference, which will be called on any error.  This
subroutine will be passed two parameters: a line number in the zone,
where the error occurred, and the error description.

=item B<soft_errors>

By default, I<parse> throws an exception on any error.  Set this
optional parameter to a true value to avoid this.  The default is false,
unless B<on_error> is also specified, in which case it is true.

=item B<quiet>

An optional parameter.  By default, on any error, the error description
is printed via warn().  Set B<quiet> to a true value if you don't want
this.  The default is false, unless B<on_error> is also specified, in
which case it is true.

=item B<debug>

An optional parameter.  If set to true, will produce some debug
printing.  You probably don't want to use that.

=back

One of B<text>, B<fh>, B<file> must be specified.  If more than one is
specified at the same time, B<fh> takes precedence over B<file>, which
takes precedence over B<text>.

As a special case, if I<parse> is called with a single, unnamed
parameter, it is assumed to be a zone text.

If I<parse> is unsuccessful, and does not throw an exception (because
either B<on_error> or B<soft_errors> was specified), I<parse> returns
undef.

The returned I<Net::DNS::RR> are normal in every respect, except that
each of them has two extra keys, Line and Lines, which correspondingly
are the line number in the zone text where the record starts, and the
number of lines the record spans.  This information can be accessed
either via hash lookup (C<$rr-E<gt>{Line}>), or via an accessor method
(C<$rr-E<gt>Line>).

=back

=head1 BUGS

The I<parse()> subroutine is not re-entrant.  Plobably will never be.

There is also no guarantee that I<parse()> will successfully parse every
zone parsable by BIND, and no guarantee that BIND will parse every zone
parsable by I<parse()>.  That said, I<parse()> appears to do the right
thing on around 50000 real life zones I tested it with.

=head1 COPYRIGHT AND LICENSE

Copyright 2003 by Anton Berezin and catpipe Systems ApS

 "THE BEER-WARE LICENSE" (Revision 42)
 <tobez@tobez.org> wrote this module.  As long as you retain this notice
 you can do whatever you want with this stuff. If we meet some day, and
 you think this stuff is worth it, you can buy me a beer in return.

 Anton Berezin

=head1 CREDITS

This module was largely inspired by the I<Net::DNS::ZoneFile> module
by Luis E. Munoz.

Many thanks to Phil Regnauld and Luis E. Munoz for discussions.

=head1 SEE ALSO

Net::DNS(3), Net::DNS::RR(3).

=cut
