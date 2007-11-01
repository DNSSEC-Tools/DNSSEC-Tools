use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;
my $lib_version;
my %MakeParams = ();
my %opts;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

# determine if we are in larger build and prepend libval-config path 
GetOptions(\%opts, 'topdir=s', 'sysconfdir=s');
$ENV{PATH} = "$opts{topdir}/validator:$ENV{PATH}" if exists $opts{topdir};

%MakeParams = InitMakeParams();

WriteMakefile(%MakeParams);

sub InitMakeParams {
    my %Params = (
		  NAME         => 'Net::DNS::SEC::Validator',
		  dist         => { SUFFIX => "gz", COMPRESS => "gzip -9f"},
		  XSPROTOARG   => '-noprototypes', 	# XXX remove later?
		  VERSION_FROM => 'Validator.pm',
		  );
    # test for libval install and get link/compile info
    my $ldflags = `libval-config --libs`;

    $Params{'LIBS'} = $ldflags;

    my $cflags = `libval-config --cflags`;
    die "error: unable to determine compile flags (check validator install)" 
	if $? or not $cflags;

    $Params{'CCFLAGS'} = $cflags;

    if (defined $opts{topdir}) {
	$Params{'INC'} = "-I$opts{topdir}/validator/include";
	$Params{'LIBS'} = "-L$opts{topdir}/validator/libval/.libs " .
	    "-L$opts{topdir}/validator/libsres/.libs " .
	    $Params{'LIBS'};
	$Params{'INC'} = "-I$opts{topdir}/validator/include";
    }

    my $dnsval_conf = `libval-config --dnsval_config`; chomp $dnsval_conf;
    my $root_hints = `libval-config --root_hints`; chomp $root_hints;
    my $resolv_conf = `libval-config --resolver_config`; chomp $resolv_conf;
    `echo 'our \$dnsval_conf = \"$dnsval_conf\"\;' >  ./defines.pl`;
    `echo 'our \$root_hints = \"$root_hints\"\;' >>  ./defines.pl`;
    `echo 'our \$resolv_conf = \"$resolv_conf\"\;' >>  ./defines.pl`;
	
    return(%Params);
}
