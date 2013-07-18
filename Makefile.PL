use 5.008008;
use ExtUtils::MakeMaker;

$ENV{AUTHOR} and require CPAN::Meta;

WriteMakefile(
	NAME              => 'AnyEvent::UA',
	VERSION_FROM      => 'lib/AnyEvent/UA.pm', # finds $VERSION
	ABSTRACT_FROM     => 'lib/AnyEvent/UA.pm', # retrieve abstract from module
	PREREQ_PM         => {
		'AnyEvent' => 5,
		'HTTP::Easy' => 0,
		'Scalar::Util' => 0,
		'common::sense' => 2,
	},
	AUTHOR            => 'Mons Anderson <mons@cpan.org>',
);
