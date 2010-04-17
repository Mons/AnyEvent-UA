#!/usr/bin/env perl

use lib::abs '..', '../../../HTTP-*/lib';
use AnyEvent::UA;
use uni::perl ':dumper';

my $ua = AnyEvent::UA->new();
warn dumper $ua;
$ua->req(GET => 'HTTP://www.google.ru:80', cb => sub {

});

$ua->{cv}->recv;