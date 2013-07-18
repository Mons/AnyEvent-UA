#!/usr/bin/env perl

use lib::abs '..', '../../../HTTP-*/lib';
use AnyEvent::UA;
use uni::perl ':dumper';

my $ua = AnyEvent::UA->new();
warn dumper $ua;
$ua->req(GET => 'HTTP://www.google.ru:80', cb => sub {
	warn dumper $_[1];
	$ua->req(GET => 'HTTP://www.google.ru:80', cb => sub {
		warn dumper $_[1];
	});
});
$ua->req(GET => 'HTTP://www.google.ru:80', cb => sub {
	warn dumper $_[1];
});
 
$ua->req(GET => 'http://i.rl0.ru/search/logo_www.gif?v=10', cb => sub {
	warn dumper $_[1];
	$ua->req(GET => 'http://i.rl0.ru/search/logo_www.gif?v=10', cb => sub {
		warn dumper $_[1];
	});
}) if 0;

$ua->{cv}->recv;