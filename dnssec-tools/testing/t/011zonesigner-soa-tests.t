# This is -*- perl -*-

use strict;
use Test::Builder;

use File::Copy;
use File::Path;
use Cwd;
use IO::Dir;
use Net::DNS::ZoneFile;

my $testZonesDirectory = "zonesigner-soas";

require "$ENV{'BUILDDIR'}/testing/t/dt_testingtools.pl";

my $testdir    = "$ENV{'BUILDDIR'}/testing/zonesigner-soa-run/";

# verbosity check
use Getopt::Std;
my %options = ();
getopts("v",\%options);

# get a list of all the test files
my @testfiles;
my $dirh = new IO::Dir($testZonesDirectory);
while (my $dirent = $dirh->read()) {
    push @testfiles, $dirent if ($dirent =~ /example.com/);
}


my $testsPerFile = 19;
# TEST object
my $test = Test::Builder->new;
$test->diag("Testing Zonesigner");
$test->plan( tests => $testsPerFile * (1 + $#testfiles));

#verbose setup for test object and dt_testingtools.
if (exists $options{v}) { $test->no_diag(0); dt_testingtools_verbose(1); }
else                    { $test->no_diag(1); dt_testingtools_verbose(0); }

# clean slate
my $origdir = getcwd;
rmtree($testdir);

# test each file
my $inputfile = "example.com";
foreach my $testfile (@testfiles) {
    mkpath($testdir) || die "unable to make(dir) $testdir";

    copy("$testZonesDirectory/$testfile","$testdir/$inputfile");
    chdir($testdir);

    $test->ok(-f "$inputfile", "$testfile was copied into place properly");

    #
    # parse the file using Net::DNS::ZoneFile to get the serial number
    #
    my $serial = get_serial_number($inputfile);
    $test->ok($serial > 0, "The serial number ($serial) was pulled out ok");

    #
    # run zonesigner the first time, generating keys
    #
    system("zonesigner -genkeys $inputfile > zonesigner.out 2>&1");
    $test->is_eq($?, 0, "zonesigner error code was ok");
    $test->ok(-f "$inputfile.signed", "$testfile was signed properly");

    #
    # check the serial numbers
    #
    check_serial_numbers($inputfile, $serial, 1);

    #
    # run zonesigner a second time, reuse keys
    #
    unlink("$inputfile.signed");
    system("zonesigner $inputfile > zonesigner.out 2>&1");
    $test->is_eq($?, 0, "zonesigner error code was ok again");
    $test->ok(-f "$inputfile.signed", "$testfile was signed properly again");

    #
    # check the serial numbers
    #
    check_serial_numbers($inputfile, $serial, 2);

    chdir($origdir);
    rmtree($testdir);
}

sub get_serial_number {
    my ($file) = @_;
    my $rrs = Net::DNS::ZoneFile::parse(file => "$inputfile",
                                        soft_errors => 1);
    $test->ok(defined($rrs), "the zone file parsed ok");
    my $serial = -1;
    foreach my $rr (@$rrs) {
	if ($rr->type() eq 'SOA') {
	    $serial = $rr->serial();
	}
    }
    return $serial;
}

sub check_serial_numbers {
    my ($file, $serial, $increment) = @_;

    #
    # check the serial numbers
    #
    my $serial2 = get_serial_number($file);
    $test->ok($serial2 > 0, "The serial number ($serial2) was pulled out ok");
    $test->ok($serial2 == $serial + $increment,
	      "The serial number ($serial2) was +$increment of the last ($serial)");

    $serial2 = get_serial_number("$file.signed");
    $test->ok($serial2 > 0,
	      "The serial number ($serial2) was pulled from the signed file");
    $test->ok($serial2 == $serial + $increment,
	      "The serial number ($serial2) was +$increment of the original ($serial)");
}



summary($test, "zonesigner-soas");
exit(0);
