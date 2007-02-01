use ExtUtils::MakeMaker;
require 5;
use Config;
use Getopt::Long;
my $lib_version;
my %MakeParams = ();
my $opts;

# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.

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
    # test for libval install - XXX this is not portable or complete
    my $ldflags;
    if (-e "/usr/lib/libval-threads.so") {
	$ldflags = "-L/usr/lib -lsres -lval-threads";
    } elsif (-e "/usr/lib/libval.so") {
	$ldflags = "-L/usr/lib -lsres -lval";
    } elsif (-e "/usr/local/lib/libval-threads.so") {
	$ldflags = "-L/usr/local/lib -lsres -lval-threads";
    } elsif (-e "/usr/lib/local/libval.so") {
	$ldflags = "-L/usr/local/lib -lsres -lval";
    }
	
    $Params{'LIBS'} = "-lnsl -lcrypto $ldflags ";
    $Params{'CCFLAGS'} = "-I/usr/local/include ";
    return(%Params);
}
