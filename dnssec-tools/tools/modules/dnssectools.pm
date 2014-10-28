#
# Copyright 2006-2014 SPARTA, Inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# DNSSEC Tools
#
# dnssectools.pm -	General functions for DNSSEC-Tools.
#
#	This module provides a place for disparate interfaces needed by
#	DNSSEC-Tools programs.
#

package Net::DNS::SEC::Tools::dnssectools;

require Exporter;
use strict;

use Mail::Send;

use Net::DNS::SEC;

use Net::DNS::SEC::Tools::conf;
use Net::DNS::SEC::Tools::defaults;
use Net::DNS::SEC::Tools::keyrec;
use Net::DNS::SEC::Tools::rollrec;

our $VERSION = "2.1";
our $MODULE_VERSION = "2.1.0";

our @ISA = qw(Exporter);

our @EXPORT = qw(
			dt_adminmail
			dt_cmdpath
			dt_filetype
			dt_parse_duration
			dt_parse_zonefile
		);

our $ZONEFILE_PARSER;

#
# List of valid DNSSEC-Tools commands.  Used by dt_cmdpath().
#
my %dtcmds =
(
	'blinkenlights'	   => 1,
	'cleanarch'	   => 1,
	'cleankrf'	   => 1,
	'dtconf'	   => 1,
	'dtconfchk'	   => 1,
	'dtdefs'	   => 1,
	'dtinitconf'	   => 1,
	'dtrealms'	   => 1,
	'expchk'	   => 1,
	'fixkrf'	   => 1,
	'genkrf'	   => 1,
	'getdnskeys'	   => 1,
	'grandvizier'	   => 1,
	'keyarch'	   => 1,
	'krfcheck'	   => 1,
	'lsdnssec'	   => 1,
	'lskrf'		   => 1,
	'lsrealm'	   => 1,
	'lsroll'	   => 1,
	'realmchk'	   => 1,
	'realmctl'	   => 1,
	'realminit'	   => 1,
	'rollchk'	   => 1,
	'rollctl'	   => 1,
	'rollerd'	   => 1,
	'rollinit'	   => 1,
	'rolllog'	   => 1,
	'rollrec-editor'   => 1,
	'rollset'	   => 1,
	'signset-editor'   => 1,
	'tachk'		   => 1,
	'timetrans'	   => 1,
	'trustman'	   => 1,
	'zonesigner'	   => 1,
);

#-----------------------------------------------------------------------------
#
# Routine:	dt_adminmail()
#
# Purpose:	This routine emails a message to the administrative user
#		listed in the DNSSEC-Tools configuration file.
#
sub dt_adminmail
{
	my $subject = shift;			# Message subject.
	my $msgbody = shift;			# Message body.

	my $sendto = "";			# Message recipient.
	my $msg;				# Message object.
	my $mh;					# Mail handler.

	my %dtconf;				# DNSSEC-Tools config file.
	my @mailargs;

	#
	# Get the message recipient.  If the caller didn't specify one,
	# we'll use the default recipient from the config file.
	#
	if(@_)
	{
		$sendto = shift;
	}
	else
	{
		#
		# Get the default DNSEEC-Tools administrative contact.
		#
		%dtconf = parseconfig();
		return(0) if(!defined($dtconf{'admin-email'}));
		$sendto = $dtconf{'admin-email'};
	}

	#
	# Ensure we really have a recipient.
	#
	return(0) if($sendto eq "");

	#
	# If things are configured to not send email, we'll return success.
	#
	return(1) if($sendto eq "nomail");

	#
	# Create the message object.
	#
	$msg = new Mail::Send;

	#
	# Add some message headers.
	#
	$msg->to($sendto);
	$msg->subject($subject);

	#
	# Open the "connection" and add the message body.
	#
	push @mailargs, $dtconf{'mailer-type'}
		if(defined($dtconf{'mailer-type'}));
	push @mailargs, 'smtp'
		if(!defined($dtconf{'mailer-type'}) &&
		    defined($dtconf{'mailer-server'}));
	push @mailargs, Server => $dtconf{'mailer-server'}
		if(defined($dtconf{'mailer-server'}));

	eval { $mh = $msg->open(@mailargs); }; return(0) if $@;
	print $mh $msgbody . "\n";

	#
	# Complete the message and send it.
	#
	eval { $mh->close; }; return(0) if $@;
	return(1);
}

#-----------------------------------------------------------------------------
# Routine:      dt_cmdpath()
# 
# Purpose:      This routine returns the path to a DNSSEC-Tools command.
#		Null is returned if the command isn't a valid DNSSEC-Tools
#		command.  Otherwise, the command's path is returned.
#
sub dt_cmdpath
{
	my $cmd = shift;			# Command to pathenate.

	return('') if($cmd eq '');
	return('') if(!$dtcmds{$cmd});
	return(dnssec_tools_default($cmd));
}

#-----------------------------------------------------------------------------
# Routine:      dt_filetype()
# 
# Purpose:      This routine returns the type of a DNSSEC-Tools file.
#		It is given a path and it counts the rollrec and keyrec
#		records contained therein.
#
#		The following return values are possible:
#
#			"keyrec"	At least one keyrec record was found
#					and no rollrec records were found.
#
#			"rollrec"	At least one rollrec record was found
#					and no keyrec records were found.
#
#			"mixed"		At least one rollrec record and at
#					least one keyrec record were found.
#					This is most likely an erroneous file.
#
#			"unknown"	No rollrec records nor keyrec records
#					were found.
#
#			"nofile"	The file doesn't exist. 
#
#		Interpretation of the result is application dependent.
#
sub dt_filetype
{
	my $path = shift;			# File to check.

	my @names;				# Record names in file.
	my $rcnt = 0;				# Count of rollrec records.
	my $kcnt = 0;				# Count of keyrec records.

	#
	# Ensure the file exists.
	#
	return("nofile") if(!-e $path);

	#
	# Get the record names as if it were a rollrec file.
	#
	@names = ();
	rollrec_read($path);
	@names = rollrec_names();
	rollrec_close();

	#
	# Count the valid record names.
	#
	foreach my $name (sort (@names))
	{
		$rcnt++ if($name ne "");
	}

	#
	# Get the record names as if it were a keyrec file.
	#
	@names = ();
	keyrec_read($path);
	@names = keyrec_names();
	keyrec_close();

	#
	# Count the valid record names.
	#
	foreach my $name (sort (@names))
	{
		$kcnt++ if($name ne "");
	}

# print "keyrec count - $kcnt\trollrec count - $rcnt\n";

	#
	# Return the type of file we found this to be.
	#
	return("rollrec") if( $rcnt && !$kcnt);
	return("keyrec")  if(!$rcnt &&  $kcnt);
	return("mixed")   if( $rcnt &&  $kcnt);
	return("unknown");
}

#-----------------------------------------------------------------------------
# Routine:	dt_parse_duration()
#
# Purpose:	This routine translates a duration given in "1w2d3h4m5s" format
#		and returns the equivalent number of seconds, or undef if the
#		duration has an invalid format.
#
sub dt_parse_duration
{
	my ($duration) = @_;
	my %duration;

	#
	# Ensure the duration is properly formatted.
	#
	return(undef) unless $duration =~ /^(?:\d+[WDHMS]?)+$/i;

	#
	# Initialize the duration hash elements to zero.
	#
	%duration = map { $_=>0 } qw(W D H M S);

	#
	# Build the duration hash.
	#
	while($duration =~ /(\d+)([WDHMS]?)/gi)
	{
		my $mod = $2 || "S";
		$duration{uc $mod} += $1;
	}

	#
	# Calculate the duration in seconds and return that value.
	#
	return($duration{S} +
		60 * ($duration{M} +
		60 * ($duration{H} +
		24 * ($duration{D} +
		 7 *  $duration{W}))));
}

#-----------------------------------------------------------------------------
# Routine:	_normalize_rrtype()
#
# Purpose:	This routine normalizes a string, returned by the accessor
#		passed, to a normal form of RR names.  If an RR name changed,
#		the accessor is called to set the new value.
#
sub _normalize_rrtype
{
	my $attr = shift;					# Accessor.

	my $old = &$attr;
	my $new = $old;

	#
	# Translate every TYPExxx known to typesbyval() to its mnemonic.
	#
	$new =~ s/\bTYPE(\d+)/Net::DNS::typesbyval($1)/ge;

	#
	# Translate every mnemonic not known to typesbyval() back to TYPExxx.
	#
	$new = join(" ", map
			{
				my $type = $_;
				eval { Net::DNS::typesbyname($type) };

				if($@)
				{		# unknown
					eval
					{
						require Net::DNS::Parameters;
						$type = "TYPE".Net::DNS::Parameters::typebyname($type);
					};

					warn "$@ - things may not validate correctly" if($@);
				}
				$type
			} split(/\s+/, $new));

	&$attr($new) if($new ne $old);
}

#-----------------------------------------------------------------------------
# Routine:	dt_parse_zonefile()
#
# Purpose:	This routine parses a given zone file using the configured
#		zone-file parser and returns an array reference containing
# 		the RRs.
#		Currently supported parsers:
#			Net::DNS::ZoneFile		(default)
#			Net::DNS::ZoneFile::Fast	("old" versions only)
#
sub dt_parse_zonefile
{
	my %options = @_;			# Parsing options.
	my $ret;				# Return value.
	my $default_parser;			# Default zonefile parser.

	#
	# Get the default zonefile parser.
	#
	$default_parser = dnssec_tools_default("zonefile-parser");

	#
	# On first call, we'll set up the zonefile-parser object.
	# We'll ensure the parser exists and maybe die if it doesn't.
	#
	if(!defined($ZONEFILE_PARSER))
	{
		my %conf = parseconfig();
		my $parser = $conf{"zonefile-parser"} || $default_parser;

		eval "require $parser";

		if($@ && ($parser ne $default_parser))
		{
			warn "zonefile parser $parser not usable; using default parser $default_parser";

			eval "require $default_parser";

			die $@ if($@);

			$ZONEFILE_PARSER = $default_parser;
		}
		elsif($@)
		{
			die $@;			# Default parser not loadable.
		}
		else
		{
			$ZONEFILE_PARSER = $parser;
		}
	}

	#
	# Parse the zonefile as required by the various parsers.
	#
	if($ZONEFILE_PARSER->isa("Net::DNS::ZoneFile::Fast"))
	{
		$ret = Net::DNS::ZoneFile::Fast::parse(%options);
	}
	elsif($ZONEFILE_PARSER->isa("Net::DNS::ZoneFile"))
	{
		#
		# Assume Net::DNS::ZoneFile calling convention.
		#
		my @args = ($options{file});
		push(@args, $options{origin}) if($options{origin});
		my $parser;
		$ret = eval {
				$parser = $ZONEFILE_PARSER->new(@args);
				return([ $parser->read ]);
			    };

		if($@)
		{
			my $line = $parser ? $parser->line : 0;
			my $err = (split(/\n/, $@))[0];

			die $@ unless $options{soft_errors};

			if(my $handler = $options{on_error})
			{
				&{$handler}($line, $err);
			}
			else
			{
				warn "Parse error at line $line: $err\n" unless $options{quiet};
			}

			return;
		}
	}
	else
	{
		warn "unrecognized zonefile parser\n" unless $options{quiet};
		return;
	}

	#
	# Normalize any resource records that were found.
	#
	if($ret && (ref($ret) eq "ARRAY"))
	{
		#
		# Normalize all RRs.
		#
		foreach my $rr (@$ret)
		{
			#
			# Type and typelist attributes provide an accessor.
			#
			foreach my $attr (qw(type typelist))
			{
				if($rr->can($attr))
				{
					_normalize_rrtype(sub{
								$rr->$attr(@_) ;
							     });
				}
			}

			#
			# SIG and RRSIG provide no accessor (except read-only
			# via AUTOLOAD) so we need to manipulate the hashref
			# ourself.
			#
			if($rr->isa("Net::DNS::RR::SIG")	||
			   $rr->isa("Net::DNS::RR::RRSIG"))
			{
				#
				# SIG and RRSIG provide no accessors
				#
				_normalize_rrtype(sub {
							$_[0] ? ($rr->{typecovered} = $_[0]) : $rr->{typecovered}
						      });
			}
		}
	}

	return($ret);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::dnssectools - General routines for the DNSSEC-Tools package.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::dnssectools;

  dt_adminmail($subject,$msgbody,$recipient);

  $zspath = dt_cmdpath('zonesigner');

  $ftype = dt_findtype($path);

  $seconds = dt_parse_duration("0w3d1h10m20s")

  $rrset = dt_parse_zonefile(file => 'example.com');

=head1 DESCRIPTION

The B<dnssectools> module provides a general set of methods for use with
DNSSEC-Tools utilities.

=head1 INTERFACES

The interfaces to the B<dnssectools> module are given below.

=over 4

=item I<dt_adminmail(subject,msgbody,recipient)>

This routine emails a message to the administrative user listed in the
DNSSEC-Tools configuration file.

I<dt_adminmail()> requires two parameters, both scalars.
The I<subject> parameter is the subject for the mail message.
The I<msgbody> parameter is the body of the mail message.

A third parameter, I<recipient>, may be given to specify the message's
recipient.  If this is not given, then the recipient will be taken from
the I<admin-email> record of the DNSSEC-Tools configuration file.
If I<recipient> is "nomail", then no message will be sent and success
will be returned.

Return values:

	1 - the message was created and sent.
	0 - an invalid recipient was specified. 

=back

It relies on the the following dnssec-tools.conf configuration parameters:

=over 4

=item I<admin-email>

The email address that the mail should come from.

=item I<mailer-type>

Should be one of: I<sendmail, smtp, qmail>.  This option is not
required and will default to trying sendmail and qmail to deliver the
mail.  If I<mailer-server> is set to a defined value but I<mailer-type> is not, then I<mailer-type> will default to 

=item I<mailer-server>

The server, if I<admin-mail> is set to I<smtp>, that the mail should
be delivered to.

=item I<dt_cmdpath(command)>

This routine returns the path to a specified DNSSEC-Tools command.
I<command> should be the name only, without any leading directories.
The command name is checked to ensure that it is a valid DNSEC-Tools command,

Return values:

	The absolute path to the command is returned if the command
	is valid.
	Null is returned if the command is not valid.

=item I<dt_filetype(path)>

This routine returns the type of the file named in I<path>.  The rollrec and
keyrec records contained therein are counted and a type determination is made.

Return values:

        "keyrec" -  At least one keyrec record was found and no
		    rollrec records were found.

        "rollrec" - At least one rollrec record was found and
		    no keyrec records were found.

        "mixed" -   At least one rollrec record and at least one
		    keyrec record were found.
                    This is most likely an erroneous file.

        "unknown" - No rollrec records nor keyrec records
                    were found.

        "nofile"  - The specified file does not exist.

=item I<dt_parse_duration(string)>

This routine translates a duration given in "1w2d3h4m5s" format and returns
the equivalent number of seconds, or undef if the duration has an invalid
format.

=item I<dt_parse_zonefile(options)>

This routine parses a given zone file using the configured zone file parser
and returns an array reference containing the RRs. The options hash is the
same as for B<Net::DNS::ZoneFile::Fast>.

The zone parser to be used depends on the setting of the I<zonefile-parser>
configuration value.  If this is not set, then the B<Net::DNS::ZoneFile::Fast>
zone parser will be used.

=back

=head1 COPYRIGHT

Copyright 2006-2014 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@tislabs.com

=head1 SEE ALSO

B<Mail::Send.pm(3)>,
B<Net::DNS::SEC::Tools::conf.pm(3)>

=cut

# Local Variables:
# tab-width: 4
# cperl-indent-level: 4
# End:
