#!/usr/bin/perl
#
# Copyright 2004 Sparta, inc.  All rights reserved.  See the COPYING
# file distributed with this software for details
#
# dnssec-tools
#
#	Option routines.
#
#	The routine in this module manipulates option lists for the
#	dnssec-tools.  After building an option list from three sources
#	(system config file, keyrec file, command-line options), a hash
#	table of options is passed back to the caller.  The caller must
#	use the options as required.
#
#

use strict;

use DNSSEC::conf;
use DNSSEC::keyrec;

use Getopt::Long;

#
# Standard options accepted by all tools in the dnssec-tools suite.
#
my @stdopts =
(
	"algorithm=s",			# Encryption algorithm
	"endtime=s",			# End-time for signed zone.
	"keyrec=s",			# Keyrec name.
	"krfile=s",			# Keyrec file.
	"kskkey=s",			# KSK key.
	"ksklength=i",			# Length of KSK.
	"kskpath=s",			# Path to KSK.
	"random=s",			# Random number generator.
	"v+",				# Verbose flag.
	"zone=s",			# Zone name.
	"zskkey=s",			# ZSK key.
	"zsklength=i",			# Length of ZSK.
	"zskpath=s",			# Path to ZSK.
);

my $firstcall	= 1;			# First-call flag.
my %cmdopts	= ();			# Options from command line.
my %saveopts	= ();			# Save-area for command-line options.

##############################################################################
#
# Routine:	tooloptions()
#
#
sub tooloptions
{
	my $krfile;				# Keyrec file to parse.
	my $krname;				# Keyrec name to snarf.
	my @csopts;				# Command-specific options.

	my $cslen;				# Length of @csopts.

	my %dnssec_opts;			# Options from config file.
	my $fullkr;				# Reference to krname's keyrec.
	my %keyrec;				# krname's keyrec.

	my @opts;				# Copy of standard options.
	my %configopts;				# Combined options.

	my @curargv;				# Current @ARGV.

	#
	# Get the arguments.  If the keyrec file arg is an empty string, then
	# we know there won't be a keyrec name.
	#
	$krfile = shift;
	if($krfile ne "")
	{
		$krname = shift;
	}
	@csopts = @_;
	$cslen = @csopts;

	#
	# Get the config file and copy the file contents.
	#
	%dnssec_opts = parseconfig();
	%configopts  = %dnssec_opts;

	#
	# If this is the first time we've been called, get the command
	# line options and save them in a module-local variable for use
	# in subsequent calls.
	#
	if($firstcall)
	{
		#
		# Copy the standard options and append any command-specific
		# options that have been given.
		#
		@opts = @stdopts;
		if($cslen > 0)
		{
			push(@opts,@csopts);
		}

		GetOptions(\%cmdopts,@opts);
		$firstcall = 0;
	}

	#
	# Read the keyrec file and pull out the specified keyrec.  If the
	# caller didn't specify a keyrec file, we'll skip this step.
	#
	if($krfile ne "")
	{
		keyrec_read($krfile);
		$fullkr = keyrec_fullrec($krname);
		%keyrec = %$fullkr;

		#
		# Delete a few internal-use-only entries from the keyrec.
		#
		delete @keyrec{'keyrec_name','keyrec_type','type'};

		#
		# Shmoosh the config file and the keyrec together,
		# starting with the config file.
		#
		foreach my $k (sort(keys(%keyrec)))
		{
			$configopts{$k} = $keyrec{$k};
		}
	}

	#
	# Mix in the options with the config data and the keyrec.
	#
	foreach my $k (sort(keys(%cmdopts)))
	{
		$configopts{$k} = $cmdopts{$k};
	}

	#
	# Return the whole swirling mess back to the user.
	#
	return(\%configopts);
}

##############################################################################
#
# Routine:	optsuspend()
#
# Purpose:	Suspend use of the command-line options.  While suspended,
#		tooloptions() will not add them to the final hash table.
#
sub optsuspend
{
	%saveopts = %cmdopts;
	%cmdopts  = ();
}

##############################################################################
#
# Routine:	optrestore()
#
# Purpose:	Restore use of the command-line options.  This will allow
#		tooloptions() to add them to the final hash table.
#
sub optrestore
{
	%cmdopts  = %saveopts;
	%saveopts = ();
}

##############################################################################
#
# Routine:	optdrop()
#
# Purpose:	Irrevocably disable use of the command-line options.
#		tooloptions() will no longer add them to the final hash table.
#
#
sub optdrop
{
	%cmdopts  = ();
	%saveopts = ();
}

1;

#############################################################################

=pod

=head1 NAME

DNSSEC::tooloptions - dnssec-tools option routines.

=head1 SYNOPSIS

  use DNSSEC::tooloptions;

  $keyrec_file = "portrigh.keyrec";
  $keyrec_name = "Kportrigh.com.+005+10988";
  @specopts = ("propagate+", "waittime=i");

  $optsref = tooloptions($keyrec_file,$keyrec_name);
  %options = %$optsref;

  $optsref = tooloptions($keyrec_file,$keyrec_name,@specopts);
  %options = %$optsref;

  $optsref = tooloptions("",@specopts);
  %options = %$optsref;

  optsuspend();

  optrestore();

  optdrop();

=head1 DESCRIPTION

The dnssec-tools support a set of options common to all the tools in the
suite.  These options may have defaults set in the B</etc/dnssec/tools.conf>
configuration file, in a I<keyrec> file, from command-line options, or from
any combination of the three.  In order to enforce a common sequence of option
interpretation, all dnssec-tools should use the I<DNSSEC::tooloptions()>
routine to initialize its options.

The I<keyrec_file> argument specifies a I<keyrec> file that will be consulted.
The I<keyrec> named by the I<keyrec_name> argument will be loaded.  If no
I<keyrec> file should be used, then I<keyrec_file> should be an empty string
and the I<keyrec_name> parameter not included.  The I<@specopts> array
contains command-specific arguments; the arguments must be in the format
prescribed by the I<Getopt::Long> Perl module.

I<tooloptions()> combines data from these three option sources into a hash
table.  The hash table is returned to the caller, which will then use the
options as needed.

The command-line options are saved between calls, so a command may call
I<tooloptions()> multiple times and still have the command-line options
included in the final hash table.  This is useful for examining multiple
I<keyrec>s in a single command.  Inclusion of command-line options may be
suspended and restored using the I<optsuspend()> and I<optrestore()> calls.
Options may be discarded entirely by calling I<optdrop()>; once dropped,
command-line options may never be restored.  Suspension, restoration, and
dropping of command-line options are only effective after the initial
I<tooloptions()> call. 

The options sources are combined in this manner:

=over 4

=item 1.  B</etc/dnssec/tools.conf>

The system-wide configuration file is read and these option values are used
as the defaults.  These options are put into a hash table, with the option
names as the hash key.

=item 2. I<Keyrec> File

If a I<keyrec> file was specified, then the I<keyrec> named by I<keyrec_name>
will be retrieved.  The I<keyrec>'s fields are added to the hash table.  Any
field whose keyword matches an existing hash key will override the existing
value.

=item 3. Command-line Options

The command-line options, specified in I<@specopts>, are parsed using
I<Getoptions()> from the I<Getopt::Long> Perl module.  These options are
folded into the hash table; again possibly overriding existing hash values.
The options given in I<@specopts> must be in the format required by
I<Getoptions()>.

=back

A reference to the hash table created in these three steps is returned to the
caller.

=head1 EXAMPLE

B</etc/dnssec/tools.conf> has these entries:

=over 4

ksklength      1024

zsklength      512

=back

portrigh.keyrec has this entry:

=over 4

key	"Kportrigh.com.+005+10988"

zsklength	"1024"

=back

B<zonesigner> is executed with this command line:

=over 4

zonesigner -ksklength 512 -zsklength 4096 -wait 600 ...  portrigh.com

=back

I<tooloptions("portrigh.keyrec","Kportrigh.com.+005+10988",("wait=i"))>
will read each option source in turn, ending up with:
    I<ksklength> 	 512
    I<zsklength> 	 4096
    I<wait> 		 600

=head1 TOOL OPTION INTERFACES

=head2 I<tooloptions(keyrec_file,keyrec_name)>

This I<tooloptions()> call builds an option hash from the system config file
and the I<keyrec> named by I<keyrec_name> from the I<keyrec_file> file.  No
command-specific options are included in the call.

=head2 I<tooloptions(keyrec_file,keyrec_name,cmd_opts)>

This I<tooloptions()> call builds an option hash from the system config file,
the I<keyrec> named by I<keyrec_name> from the I<keyrec_file> file, and the
command-specific options given in I<cmd_opts>.

=head2 I<tooloptions("",cmd_opts)>

This I<tooloptions()> call builds an option hash from the system config file
and the command-specific options given in I<cmd_opts>.  No I<keyrec> file is
consulted.  Since no I<keyrec_file> is specified, the I<keyrec_name> argument
must not be given.

=head2 I<optsuspend()>

Suspend inclusion of the command-line options in building the final hash
table of responses.

=head2 I<optrestore()>

Restore inclusion of the command-line options in building the final hash
table of responses.

=head2 I<optdrop()>

Discard the command-line options.  They will no longer be available for
inclusion in building the final hash table of responses for this execution
of the command.

=head1 AUTHOR

Wayne Morrison, tewok@users.sourceforge.net

=head1 SEE ALSO

zonesigner(1)

DNSSEC::conf(3), DNSSEC::keyrec(3), Getopt::Long(3)

=cut
