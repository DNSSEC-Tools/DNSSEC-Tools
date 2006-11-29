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
                                    
    if (not -r '/usr/local/lib/libsres.so' or 
	not -r '/usr/local/lib/libval.so') {
	die "error: must install dnssec-tools validator libraries first.";
    }

    $Params{'LIBS'} = "-lnsl -lcrypto -L/usr/local/lib -lsres -lval ";
    $Params{'CCFLAGS'} = "-I/usr/local/include ";
    return(%Params);
}
