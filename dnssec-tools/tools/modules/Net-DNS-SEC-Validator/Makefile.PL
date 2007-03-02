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
		  MAN3PODS     => { 'Validator.pm' => 
				   '$(INST_MAN3DIR)/Net_DNS_SEC_Validator.3' },
		  XSPROTOARG   => '-noprototypes', 	# XXX remove later?
		  VERSION_FROM => 'Validator.pm',
		  );
    # test for libval install and get link/compile info
    my $ldflags = `libval-config --libs`;
    die "error: unable to determine link flags (check validator install)" 
	if $? or not $ldflags;
	
    $Params{'LIBS'} = $ldflags;

    my $cflags = `libval-config --cflags`;
    die "error: unable to determine complile flags (check validator install)" 
	if $? or not $cflags;

    $Params{'CCFLAGS'} = $cflags;

    if (defined $opts{topdir}) {
	$Params{'INC'} = "-I$opts{topdir}/validator/include";
	$Params{'LIBS'} = "-L$opts{topdir}/validator/libval/.libs " .
	    "-L$opts{topdir}/validator/libsres/.libs " .
	    $Params{'LIBS'};
	$Params{'INC'} = "-I$opts{topdir}/validator/include";
    }
	
    return(%Params);
}
