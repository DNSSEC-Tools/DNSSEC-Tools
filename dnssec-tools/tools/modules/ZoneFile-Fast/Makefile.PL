use ExtUtils::MakeMaker;
WriteMakefile(
    NAME		=> 'Net::DNS::ZoneFile::Fast',
    VERSION_FROM 	=> 'Fast.pm',
    # Net::DNS{,::SEC} keeps changing internals by adding and removing
    # dots in certain fields, etc...  That means we need to require
    # certain versions explicitly.
    PREREQ_PM		=> { 'Net::DNS'      => 0.65,
			     'Net::DNS::SEC' => 0.15,
			     'MIME::Base64'  => 0,
                             'IO::File'      => 0,
			   },

	META_MERGE => {
	    'meta-spec' => { version => 2 },
	     resources => {
	         repository => {
	             type => 'svn',
	             url  => 'https://dnssec-tools.org/svn/dnssec-tools/',
	             web  => 'https://dnssec-tools.org/svn/dnssec-tools/',
	         },
	     },
	},
);
