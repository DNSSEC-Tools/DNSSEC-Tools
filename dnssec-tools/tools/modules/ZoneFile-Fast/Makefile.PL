use ExtUtils::MakeMaker;
WriteMakefile(
    NAME			=> 'Net::DNS::ZoneFile::Fast',
    VERSION_FROM 	=> 'Fast.pm',
	PREREQ_PM		=> { 'Net::DNS' => 0, },
);
