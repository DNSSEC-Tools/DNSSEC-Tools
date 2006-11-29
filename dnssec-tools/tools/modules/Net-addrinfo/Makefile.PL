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
		  NAME         => 'Net::addrinfo',
		  dist         => { SUFFIX => "gz", COMPRESS => "gzip -9f"},
		  MAN3PODS     => { 'addrinfo.pm' => 
				    '$(INST_MAN3DIR)/Net_addrinfo.3' },
		  XSPROTOARG   => '-noprototypes', 	# XXX remove later?
		  VERSION_FROM => 'addrinfo.pm',
		  );
                                    
    return(%Params);
}
