#!/usr/bin/perl

use IO::Dir;
use strict;

my $downloaddir = "/var/www/html/dnssec-tools.org/releases/";

my %stuff;

#
# print http headers
#
print "Content-Type: text/html\n\n";


#
# open the download directory 
#
my $dirh = IO::Dir->new($downloaddir);
if (!defined($dirh)) {
    print "<h2>Error in Generating a Download Listing</h2>\n";
    print "<p>please contact an administrator</p>\n";
    exit 1;
}

#
# loop through the directory contents collecting info
#

my $dir;
while (defined($dir = $dirh->read)) {
    next if ($dir =~ /^\./);

    my $subversion = "&nbsp;";

    my ($name, $ver, $type) = ($dir =~ /([^\d]+)-([-\.\drcpre]+)\.(.*)/);
    if ($ver =~ s/-(\d+)//) {
	$subversion = $1;
    }

    if ($type) {
	$stuff{$ver}{$subversion}{$name}{$type} = [$dir,$subversion];
    }
#    print "<pre>$ver}{$name}{$type = $dir</pre>\n";
}

#
# print the headers
#
print "<html>
<head>
  <title>DNSSEC-Tools Releases</title>
  <link rel=\"StyleSheet\" type=\"text/css\" href=\"/dnssec-tools.css\" />
</head>
<body>
<h2>Downloads</h2>

<p> The files available for download are listed below.  All release
contain source code, if you wish to install from source (installing
any dependencies needed first).  There are also some pre-compiled
binary packages as well as pre-compilred versions of single
tools.</p>

<p>Pre-compiled single-tool binaries may need to have the execute bit
turned on (use <i>chmod a+x FILE</i> on unix).  The first launch of a
pre-compiled binary will take a bit to run as it unpacks various files
to a tempororay directory.  Subsequent launches should execute much faster.</p>

<h4>Jump points:</h4>
<ul>
<li><a href=\"#dtcdown\">Complete DNSSEC-Tools Package Downloads</a></li>
<li><a href=\"#dtidown\">Individual DNSSEC-Tools Component Downloads</a></li>
<li><a href=\"#dtadown\">DNSSEC Instrumented Application Downloads</a></li>
</ul>

<a name=\"dtcdown\" />
<h2>Available DNSSEC-Tools Downloads</h2>
";

#
# print each release in a table, sorting the main releases to the top
#

# table header
output_release('dnssec-tools', '(tar.gz|zip|src.rpm)', 'Source');
print "</table>\n";

print "<a name=\"dtidown\" />
<h2>Available DNSSEC-Tools Individual Component Downloads</h2>
";


output_release('(donuts|zonesigner|rollerd)');

print "<a name=\"dtadown\" />
<h2>Available DNSSEC Instrumented Application Downloads</h2>
";

output_release('.','src.rpm', 'Source');

sub output_release {
    my ($include_pattern, $primary_pattern, $primereltype, $secondreltype) = @_;

    $primereltype ||= 'Binary';
    $secondreltype ||= 'Binary';

    print "<table class=\"bordered\"><th>Version</th><th>Subversion</th><th>Name</th><th>Release<br />Type</th><th>File<br />Type</th><th>Architecture</th></tr>\n";

    # each release
    foreach my $ver (sort sort_versions keys(%stuff)) {

	foreach my $subver (sort sort_subversions keys(%{$stuff{$ver}})) {

	    # do main packaging first (source, etc)
	    foreach my $name (sort keys(%{$stuff{$ver}{$subver}})) {
		
		next if ($include_pattern &&
			 $name !~ /$include_pattern/);

		foreach my $type 
		  (sort {
		      # first by subversion in reverse
		      my $result = $stuff{$ver}{$subver}{$name}{$b}[1] <=>
			$stuff{$ver}{$subver}{$name}{$a}[1];
		      return $result if ($result ne '0');
		      # then by type
		      return $a cmp $b;
		  } keys(%{$stuff{$ver}{$subver}{$name}})) {

		      next if ($primary_pattern &&
			       $type !~ /$primary_pattern/);

		      my ($archtype, $filetype) =
			($type =~ /(.*)\.([a-zA-Z]+)/);

		      print "<tr><td>$ver</td>";
		      print "<td>$stuff{$ver}{$subver}{$name}{$type}[1]</td>";
		      print "<td><a href=\"$stuff{$ver}{$subver}{$name}{$type}[0]\">$stuff{$ver}{$subver}{$name}{$type}[0]</a></td>";
		      print "<td>$primereltype</td><td>$filetype</td><td>$archtype</td></tr>\n";
		      delete $stuff{$ver}{$subver}{$name}{$type}
		  }
	    }


	    # other releases
	    foreach my $name (sort keys(%{$stuff{$ver}{$subver}})) {

		next if ($include_pattern &&
			 $name !~ /$include_pattern/);

		foreach my $type 
		  (sort {
		      # first by subversion in reverse
		      my $result = $stuff{$ver}{$subver}{$name}{$b}[1] <=>
			$stuff{$ver}{$subver}{$name}{$a}[1];
		      return $result if ($result ne '0');
		      # then by type
		      return $a cmp $b;
		  } keys(%{$stuff{$ver}{$subver}{$name}})) {

		      my ($archtype, $filetype) =
			($type =~ /(.*)\.([a-zA-Z]+)/);
		      # deal with other types here

		      print "<tr><td>$ver</td>";
		      print "<td>$stuff{$ver}{$subver}{$name}{$type}[1]</td>";
		      print "<td><a href=\"$stuff{$ver}{$subver}{$name}{$type}[0]\">$stuff{$ver}{$subver}{$name}{$type}[0]</a></td>";
		      print "<td>$secondreltype</td><td>$filetype</td><td>$archtype</td></tr>\n";
		      delete $stuff{$ver}{$subver}{$name}{$type}
		  }
	    }
	}
    }
    print "</table>\n";
}

# sorting version numbers by newest first
sub sort_versions {
    my $aroot = $a;
    my $broot = $b;
    $aroot =~ s/.(pre|rc).*//;
    $broot =~ s/.(pre|rc).*//;
#    print "<pre>$aroot $broot $a $b</pre>" if ($a eq '1.4.rc1' || $b eq '1.4.rc1');
    if ($aroot eq $broot) {
	return 1 if ($a =~ /pre/ && $b !~ /pre/); # pre-releases issued first
	return 1 if ($a =~ /rc/ && $b !~ /rc/); # then rc releases
    }
    return $broot <=> $aroot if (($broot <=> $aroot) != 0);
    return $broot cmp $aroot
}

sub sort_subversions {
    return 1  if ($a ne $b && $b eq '');
    return -1 if ($a ne $b && $a eq '');
    return $b <=> $a;
}
