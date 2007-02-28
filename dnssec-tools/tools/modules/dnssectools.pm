#
# Copyright 2006-2007 SPARTA, Inc.  All rights reserved.  See the COPYING
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

use Net::DNS::SEC::Tools::conf;

our $VERSION = "0.9";

our @ISA = qw(Exporter);

our @EXPORT = qw(
			dt_adminmail
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
	# Create the message object.
	#
	$msg = new Mail::Send;

	#
	# Add some message headers.
	#
	$msg->to($sendto);
	$msg->subject($subject);

	#
	# Add the message body.
	#
	$mh = $msg->open;
	print $mh $msgbody . "\n";

	#
	# Complete the message and send it.
	#
	$mh->close;
	return(1);
}

1;

#############################################################################

=pod

=head1 NAME

Net::DNS::SEC::Tools::dnssectools - General routines for the DNSSEC-Tools package.

=head1 SYNOPSIS

  use Net::DNS::SEC::Tools::dnssectools;

  dt_adminmail($subject,$msgbody,$recipient);

=head1 DESCRIPTION

The B<Net::DNS::SEC::Tools::rollmgr> module provides standard,
platform-independent methods for a program to communicate with DNSSEC-Tools'
B<rollerd> rollover manager.  There are three interface classes described
here:  general interfaces, logging interfaces, and communications interfaces.

=head1 GENERAL INTERFACES

The interfaces to the B<Net::DNS::SEC::Tools::dnssectools> module are given
below.

=over 4

=item I<dt_adminmail(subject,msgbody,recipient)>

This routine emails a message to the administrative user
listed in the DNSSEC-Tools configuration file.

I<dt_adminmail()> requires two parameters, both scalars.
The I<subject> parameter is the subject for the mail message.
The I<msgbody> parameter is the body of the mail message.

A third parameter, I<recipient>, may be given to specify the message's
recipient.  If this is not given, then the recipient will be taken from
the I<admin-email> record of the DNSSEC-Tools configuration file.

Return values:

	1 - the message was created and sent.
	0 - an invalid recipient was specified. 

=back

=head1 COPYRIGHT

Copyright 2006-2007 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

B<Mail::Send.pm(3)>,
B<Net::DNS::SEC::Tools::conf.pm(3)>

=cut
