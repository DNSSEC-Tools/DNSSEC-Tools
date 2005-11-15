use ExtUtils::MakeMaker;
WriteMakefile(
    NAME		=> 'Net::DNS::ZoneFile::Fast',
    VERSION_FROM 	=> 'Fast.pm',
    PREREQ_PM		=> { 'Net::DNS'      => 0,
			     'Net::DNS::SEC' => 0,
			     'MIME::Base64'  => 0,
                             'IO::File'      => 0,
			   },
);
