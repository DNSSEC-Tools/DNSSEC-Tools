#!/usr/bin/perl
# Copyright 2004-2005 SPARTA, Inc.  All rights reserved.
# See the COPYING file included with the DNSSEC-Tools package for details.

use GraphViz;
use IO::Socket::INET;
use IO::File;
use Getopt::Long;

########################################################
# Globals

my $gv;
my $name;
my $class; 
my $type;
my $status;
my $dest;
my $i;
my $socket;
my $count;
my $edge_str;
my $giffile;
my $htmlfile;
my $htmlfh;
my $giftmp;

########################################################
# Defaults

my %opts = (
	h => "127.0.0.1",
	p => "1053",
	f => "val_log_map.html",
	g => "val_log_map.gif",
	r => 5,
	s => 0
);


########################################################
# main

GetOptions(\%opts, "h=s", "p=s", "f=s", "g=s", "r=i", "s");

$gv = GraphViz->new(rankdir => 1, edge => { fontsize => '9'});
$gv->add_node('Validator');
$count = 0;
$changed = 1;

$giffile = $opts{'g'};
$htmlfile = $opts{'f'};
$refresh = $opts{'r'};
# create an HTML file with the image and 
# with auto refresh set to 5 seconds
$htmlfh = new IO::File(">$htmlfile");
print $htmlfh "<html>\n<head>\n".
	"<title>Validator Results</title>\n".
	"<meta http-equiv=\"refresh\" content=\"$refresh\">\n".
	"</head>\n".
	"<body> <img src=\"$giffile\" alt=\"Validator Status\"> </body>\n".
	"</html>";
$htmlfh->close;

# check if socket operation is desired
if($opts{'s'} == 1) {
	$local_host = $opts{'h'};
	$local_port = $opts{'p'};
	$socket = IO::Socket::INET->new(LocalAddr => $local_host,
                                LocalPort => $local_port,
                                Proto    => "udp",
                                Type     => SOCK_DGRAM)
    	or die "Couldn't bind to $local_host:$local_port\n";

	while ($_=<$socket>) {
		update_image($_);
	}

	# Never reached
	close($socket);
}

# Read from stdin
while ($_=<STDIN>) {
	update_image($_);
}


########################################################
# Read the log message and build an html file containing 
# the updated graph
#
sub update_image {

	# update the image only when something has changed
	if($changed) {
		$giftmp = $giffile . "tmp"; 

		# generate the gif file
		$gv->as_gif($giftmp);
		rename($giftmp, $giffile);
	}
	
	$changed = 0;
	
	# Look for only messages of the following type
	if (/\s*name=(\S+)\s*class=(\S+)\s*type=(\S+)\s*from-server=(\S+)\s*(status)=(\S+)/) {
		$log[$count] =  "$1 $2 $3 $4 $6" ;
	}
	else {
		# received data that this utility has no use for
		return;
	}

	# remove duplicates from the array so that 
	# all edges on the graph are different
	my %hash = map { $_, 1 } @log;
	@log = keys %hash;

	# Check if something new was added 
	if($count == ($#log + 1)) {
		return;
	}

	$changed = 1;
	$count = $#log + 1;

	# add the node and an edge from the Validator
	($name, $class, $type, $dest, $status) = ($1, $2, $3, $4, $6); 
	$gv->add_node($dest);
	$edge_str = $name . ":" . $class . ":" . $type . ":" . "$status" ;
	$gv->add_edge('Validator', $dest, label => $edge_str, decorateP => '1', getlineattr($status));
}


#############################################################
# get the edge properties based on the error status passed as 
# the parameter
#
sub getlineattr {

	my %prop;
	my $val_status;
	$val_status = shift;

	$prop{'dir'} = 'back';

	if (($val_status eq "VALIDATE_SUCCESS") ||
			($val_status eq "NONEXISTENT_NAME")) { 
		$prop{'color'} =  "green";
		$prop{'style'} = 'bold';
	} 
	elsif ($val_status eq "VERIFIED") { 
		$prop{'color'} =  "green";
	} 
	elsif ($val_status eq "TRUST_KEY") { 
		$prop{'color'} =  "black";
		$prop{'style'} = 'bold';
	} 
	elsif (($val_status eq "VALIDATION_ERROR") || 
			($val_status eq "BOGUS_PROOF") || 
			($val_status eq "BOGUS_PROVABLE") ||
			($val_status eq "SECURITY_LAME")) {
		$prop{'color'} = "red";
		$prop{'style'} = 'bold';
	} 
	elsif (($val_status eq "RRSIG_EXPIRED") ||
			($val_status eq "RRSIG_NOTYETACTIVE") ||
			($val_status eq "RRSIG_VERIFY_FAILED")) {
		$prop{'color'} =  "red";
	} 
	elsif (($val_status eq "DNS_ERROR") ||
			($val_status eq "RRSIG_MISSING")) { 
		$prop{'color'} =  "red";
		$prop{'style'} = 'dashed';
	} 
	elsif ($val_status eq "NO_TRUST_ANCHOR") { 
		$prop{'color'} =  "brown";
		$prop{'style'} = 'bold';
	} 
	elsif ($val_status eq "UNEVALUATED") {
		$prop{'color'} =  "yellow";
		$prop{'style'} = 'dashed';
	} 
	else {
		# unknown error is shown in yellow
		$prop{'color'} =  "yellow";
		# display the error if we don't know how to display the status
		print "$val_status \n";
	}

	return %prop;
}


=head1 NAME

drawvalmap - Generate a graphical output of validation status values
             encountered by the validator library.

=head1 SYNOPSIS

./drawvalmap.pl 

=head1 DESCRIPTION

drawvalmap.pl is a simple utility that can be used to display the query assertion status 
in a graphical format. The input to this script is a set of log messages that 
can be read either from STDIN or from a socket. The default is to read it from STDIN.
The output is an HTML file containing an image of the various validator assertion 
status values. The HTML file auto-refreshes every five seconds so that changes to 
the validator graph can be constantly tracked. The drawvalmap.pl script executes 
in an infinite loop and never returns on its own.  

This script can be started from the command line by typing

bash# ./drawvalmap.pl

It would not be uncommon to use this script for
troubleshooting purposes in which case output generated by a driver 
program would be "piped" to this script in the manner shown below.

bash# ${LIBVAL}/bin/driver 2>&1 |  ./drawvalmap.pl

In each case the script reads log messages from STDIN, generating
a default HTML file with the name val_log_map.html. The gif containing
the actual validator map has the default name as val_log_map.gif. Both
of these defaults can be modified by using the command-line flags 
described below. 

=head1 OPTIONS

=over

=item -f

This changes the name of .html file to the given value.

=item -g

This changes the name of .gif file to the given value.

=item -r

This changes the refresh period in the HTML file to the given value.

=item -s

This changes the mode of operation to read input from a socket.
The default address and port to which drawvalmap binds is
127.0.0.1:1053 

=item -h

This changes the address to which drawvalmap binds itself to
the specified value. This option takes effect only if the
-s option is also specified.

=item -p

This changes the port to which drawvalmap binds itself to
the specified value. This option takes effect only if the
-s option is also specified.

=back
  

=head1 PRE-REQUISITES

GraphViz

=head1 COPYRIGHT

Copyright 2005 SPARTA, Inc.  All rights reserved.
See the COPYING file included with the DNSSEC-Tools package for details.

=cut


 
