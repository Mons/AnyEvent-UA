#!/usr/bin/env perl
use strict;
use warnings;

use lib::abs '..';

use AnyEvent::UA;
use AnyEvent;
use Data::Dumper;
use URI::Escape;


my $ua= AnyEvent::UA->new(
  headers=> {
    'user-agent' => 'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.93 Safari/537.36' 
  },
);

my %url= (
  last_date => 'http://quote.rbc.ru/cgi-bin/front/content/cash_currency_rates_get_last_date/',
  #last_date => 'http://android.apis.google.com/c2dm/send', # This URL requires Content-Length header, which is set automatically for POST requests
);

my %post_data = (
  last_date=> {
    city              => 1, 
    currency          => 3, 
    summa             => 3, 
    period            => 15,
    pagerLimiter      => 15,
    pageNumber        => 15,
  },
);


sub post_body{
  my $data = shift;
  my $body = join '&', map { my ($k,$v)=($_,$data->{$_}); utf8::encode($v); join '=', uri_escape($k), uri_escape($v)} keys %$data;
  return $body;
}

$ua->{headers}{referer} = 'http://google.com';
$ua->req(POST=>$url{last_date}, body=>post_body($post_data{last_date}), cb=> sub {
  my ($body, $headers) = (shift, shift);
  if ($headers->{Status} == 200) {
    warn Dumper $body;
  } else {
    warn 'POST request failed: '. Dumper ($headers, $body);
  }
  $ua->{cv}->send;
});

$ua->{cv}->recv;
