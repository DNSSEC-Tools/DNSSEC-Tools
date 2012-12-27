# This is -*- perl -*-

use strict;
use Test::Builder;

use File::Copy;
use File::Path;

use IO::Dir;

require "$ENV{'BUILDDIR'}/testing/t/dt_testingtools.pl";

my $testdir    = "$ENV{'BUILDDIR'}/testing/zonesigner-soa-run/";

# verbosity check
use Getopt::Std;
my %options = ();
getopts("v",\%options);

# get a list of all the test files
my @testfiles;
my $dirh = new IO::Dir("zonesigner-soas");
while (my $dirent = $dirh->read()) {
    push @testfiles, $dirent if ($dirent =~ /.com$/);
}

my $testsPerFile = 1;

# TEST object
my $test = Test::Builder->new;
$test->diag("Testing Zonesigner");
$test->plan( tests => $testsPerFile * (1 + $#testfiles));

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }

# clean slate
rmtree($testdir);

# test each file
foreach my $testfile (@testfiles) {
    mkpath($testdir) || die "unable to make(dir) $testdir";
    $test->is_eq(1,0, "testing of $testfile");
    rmtree($testdir);
}

summary($test, "zonesigner-soas");
exit(0);
