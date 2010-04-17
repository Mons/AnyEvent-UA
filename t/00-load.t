#!perl -T

use Test::More tests => 1;

BEGIN {
    use_ok( 'AnyEvent::UA' ) || print "Bail out!
";
}

diag( "Testing AnyEvent::UA $AnyEvent::UA::VERSION, Perl $], $^X" );
