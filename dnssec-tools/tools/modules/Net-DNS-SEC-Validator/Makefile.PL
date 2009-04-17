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

local $LD_LPATH;
$LD_LPATH = "$opts{topdir}/validator/libsres/.libs:$opts{topdir}/validator/libval/.libs:\$LD_LIBRARY_PATH" if exists $opts{topdir};


sub MY::test_via_harness {
  my($self, $perl, $tests) = @_;
  local $_ = $self->MM::test_via_harness($perl, $tests);
  s/PERL_DL_NONLAZY=1/$& LD_LIBRARY_PATH=$LD_LPATH/g if defined $LD_LPATH;
  return $_;
}

sub MY::test_via_script {
  my($self, $perl, $tests) = @_;
  local $_ = $self->MM::test_via_script($perl, $tests);
  s/PERL_DL_NONLAZY=1/$& LD_LIBRARY_PATH=$LD_LPATH/g if defined $LD_LPATH;
  return $_;
}


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
    }

    my $dnsval_conf = `libval-config --dnsval_config`; chomp $dnsval_conf;
    my $root_hints = `libval-config --root_hints`; chomp $root_hints;
    my $resolv_conf = `libval-config --resolver_config`; chomp $resolv_conf;
    `echo 'our \$dnsval_conf = \"$dnsval_conf\"\;' >  ./defines.pl`;
    `echo 'our \$root_hints = \"$root_hints\"\;' >>  ./defines.pl`;
    `echo 'our \$resolv_conf = \"$resolv_conf\"\;' >>  ./defines.pl`;
	
    return(%Params);
}

