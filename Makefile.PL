use inc::Module::Install;

name     'AnyEvent-UA';
all_from 'lib/AnyEvent/UA.pm';
author   q{Mons Anderson <mons@cpan.org>};
license  'perl';

build_requires 'Test::More';

auto_install;

WriteAll;

