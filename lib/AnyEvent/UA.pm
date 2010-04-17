package AnyEvent::UA;

#use strict;
#use warnings;
use uni::perl ':dumper';

use AE;
use AnyEvent::DNS;
use AnyEvent::Socket;
use AnyEvent::Handle;
use HTTP::Easy::Headers;
use HTTP::Easy::Cookies;


=head1 NAME

AnyEvent::UA - The great new AnyEvent::UA!

=head1 VERSION

Version 0.01

=cut

our $VERSION = '0.01';


=head1 SYNOPSIS

Quick summary of what the module does.

Perhaps a little code snippet.

    use AnyEvent::UA;

    my $foo = AnyEvent::UA->new();
    ...

=cut

sub new {
	my $pk = shift;
	my $self = bless {}, $pk;
	my %args = @_;
	$self->{headers} = {
#		'accept'          => 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
#		'user-agent'      => 'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.0.10) Gecko/2009042315 Firefox/3.0.10',
		'referer'         => undef,
#		'accept-language' => 'ru,en-us;q=0.8,en;q=0.5,ru-ru;q=0.3',
#		'accept-encoding' => 'gzip',
#		'accept-charset'  => 'windows-1251,utf-8;q=0.7,*;q=0.7',
		%{ $args{headers} || {} },
	};
	$self->{cv} = $args{cv} || AE::cv;
	$self->{cookie} //= HTTP::Easy::Cookies->new();
	#$self->{auth} = {};
	#$self->{requests} = [];
	#$self->{domain} = $args{domain} || '.odnoklassniki.ru';
	$self->{debug} = $args{debug} // 1;
	$self->{proxy} = $args{proxy} if exists $args{proxy};
	$self;
}

=for rem
sub http_request($$@) {
   my $cb = pop;
   my ($method, $url, %arg) = @_;

   $arg{tls_ctx} = $TLS_CTX_LOW  if $arg{tls_ctx} eq "low" || !exists $arg{tls_ctx};
   $arg{tls_ctx} = $TLS_CTX_HIGH if $arg{tls_ctx} eq "high";

   $method = uc $method;

   if (my $hdr = $arg{headers}) {
      while (my ($k, $v) = each %$hdr) {
         $hdr{lc $k} = $v;
      }
   }

   my $recurse = exists $arg{recurse} ? delete $arg{recurse} : $MAX_RECURSE;

   return $cb->(undef, { Status => 599, Reason => "Too many redirections", URL => $url })
      if $recurse < 0;

   my $proxy   = $arg{proxy}   || $PROXY;
   my $timeout = $arg{timeout} || $TIMEOUT;


   if ($arg{body_cb}) {
      defined $hdr{"content-length"} or return $cb->(undef, { Status => 599, Reason => "Content-Length required", URL => $url });
      exists $arg{body} and warn("Don't pass body, when use body_cb"),delete $arg{body};
   } else {
      $hdr{"content-length"} = length $arg{body}; delete $hdr{"content-length"} if $hdr{"content-length"} == 0 and $method eq 'GET';
   }

   my %state = (connect_guard => 1);

   _get_slot $uhost, sub {
      $state{slot_guard} = shift;

      return unless $state{connect_guard};

      $state{connect_guard} = AnyEvent::Socket::tcp_connect $rhost, $rport, sub {
         $state{fh} = shift
            or do {
               my $err = "$!";
               %state = ();
               return $cb->(undef, { Status => 599, Reason => $err, URL => $url });
            };

         pop; # free memory, save a tree

         return unless delete $state{connect_guard};

         # get handle
         $state{handle} = new AnyEvent::Handle
            fh       => $state{fh},
            timeout  => $timeout,
            peername => $rhost,
            tls_ctx  => $arg{tls_ctx};

         # limit the number of persistent connections
         # keepalive not yet supported
         if ($KA_COUNT{$_[1]} < $MAX_PERSISTENT_PER_HOST) {
            ++$KA_COUNT{$_[1]};
            $state{handle}{ka_count_guard} = AnyEvent::Util::guard {
               --$KA_COUNT{$_[1]}
            };
            $hdr{connection} = "keep-alive";
         } else {
            delete $hdr{connection};
         }

         # (re-)configure handle
         $state{handle}->on_error (sub {
            %state = ();
            $cb->(undef, { Status => 599, Reason => $_[2], URL => $url });
         });
         $state{handle}->on_eof (sub {
            %state = ();
            $cb->(undef, { Status => 599, Reason => "Unexpected end-of-file", URL => $url });
         });

         $state{handle}->starttls ("connect") if $rscheme eq "https";

         # handle actual, non-tunneled, request
         my $handle_actual_request = sub {
            $state{handle}->starttls ("connect") if $uscheme eq "https" && !exists $state{handle}{tls};

            # send request
            $DEBUG_SEND->($url,$method,$rpath,\%hdr,$arg{body}) if defined $DEBUG_SEND;
            $state{handle}->push_write (
               "$method $rpath HTTP/1.0\015\012"
               . (join "", map "\u$_: $hdr{$_}\015\012", grep defined $hdr{$_}, keys %hdr)
               . "\015\012"
               . (delete $arg{body})
            );
            if ($arg{body_cb}) {
               my $written = 0;
               my $need = $hdr{"content-length"};
               $state{handle}->on_drain(sub {
                  $arg{body_cb}(sub {
                     shift if @_ and length $_[0] == 0;
                     use bytes;
                     if (@_) {
                        my $chunk = shift;
                        my $left = $need - $written;
                        $written += ( my $length = length $chunk );
                        #warn "Written chunk=$length. now have written=$written and left=".($need - $written);
                        if ($written >= $need) {
                           if ($written > $need) {
                              $chunk = substr($chunk,0,$left);
                              warn "got more data $written, than content-length $need, truncated at @{[ (caller)[1,2] ]}\n";
                           }
                           $state{handle}->on_drain(undef);
                           undef $arg{body_cb};
                        }
                        $state{handle}->push_write($chunk);
                     } else {
                        $state{handle}->on_drain(undef);
                        undef $arg{body_cb};
                        if ($written < $need) {
                           return (%state = (), $cb->(undef, { Status => 599, Reason => "Insufficient ".($need-$written)." bytes data from body_cb. need $need, got $written", URL => $url }));
                        }
                     }
                  });
               });
               %state or return;
            }

            %hdr = (); # reduce memory usage, save a kitten

            # status line
            $state{handle}->push_read (line => $qr_nl, sub {
               $_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) (?: \s+ ([^\015\012]*) )?/ix
                  or return (%state = (), $cb->(undef, { Status => 599, Reason => "Invalid server response ($_[1])", URL => $url }));

               my %hdr = ( # response headers
                  HTTPVersion => ",$1",
                  Status      => ",$2",
                  Reason      => ",$3",
                  URL         => ",$url"
               );

               # headers, could be optimized a bit
               $state{handle}->unshift_read (line => $qr_nlnl, sub {
                  for ("$_[1]") {
                     y/\015//d; # weed out any \015, as they show up in the weirdest of places.

                     # things seen, not parsed:
                     # p3pP="NON CUR OTPi OUR NOR UNI"

                     $hdr{lc $1} .= ",$2"
                        while /\G
                              ([^:\000-\037]*):
                              [\011\040]*
                              ((?: [^\012]+ | \012[\011\040] )*)
                              \012
                           /gxc;

                     /\G$/
                       or return (%state = (), $cb->(undef, { Status => 599, Reason => "Garbled response headers", URL => $url }));
                  }

                  substr $_, 0, 1, ""
                     for values %hdr;

                  # redirect handling
                  # microsoft and other shitheads don't give a shit for following standards,
                  # try to support some common forms of broken Location headers.
                  if ($hdr{location} !~ /^(?: $ | [^:\/?\#]+ : )/x) {
                     $hdr{location} =~ s/^\.\/+//;

                     my $url = "$rscheme://$uhost:$uport";

                     unless ($hdr{location} =~ s/^\///) {
                        $url .= $upath;
                        $url =~ s/\/[^\/]*$//;
                     }

                     $hdr{location} = "$url/$hdr{location}";
                  }

                  my $redirect;

                  if ($recurse) {
                     if ($hdr{Status} =~ /^30[12]$/ && $method ne "POST") {
                        # apparently, mozilla et al. just change POST to GET here
                        # more research is needed before we do the same
                        $redirect = 1;
                     } elsif ($hdr{Status} == 303) {
                        # even http/1.1 is unclear on how to mutate the method
                        $method = "GET" unless $method eq "HEAD";
                        $redirect = 1;
                     } elsif ($hdr{Status} == 307 && $method =~ /^(?:GET|HEAD)$/) {
                        $redirect = 1;
                     }
                  }

                  my $finish = sub {
                     $state{handle}->destroy if $state{handle};
                     %state = ();

                     # set-cookie processing
                     if ($arg{cookie_jar}) {
                        for ($_[1]{"set-cookie"}) {
                           # parse NAME=VALUE
                           my @kv;

                           while (/\G\s* ([^=;,[:space:]]+) \s*=\s* (?: "((?:[^\\"]+|\\.)*)" | ([SMTWF][a-z][a-z],\s\d\d[\s-][JFMAJSOND][a-z][a-z][\s-]\d\d\d\d\s\d\d:\d\d:\d\d\sGMT|[^=;,[:space:]]*) )/gcxs) {#"
                              my $name = $1;
                              my $value = $3;

                              unless ($value) {
                                 $value = $2;
                                 $value =~ s/\\(.)/$1/gs;
                              }

                              push @kv, $name => $value;

                              last unless /\G\s*;/gc;
                           }

                           last unless @kv;

                           my $name = shift @kv;
                           my %kv = (value => shift @kv, @kv);

                           my $cdom;
                           my $cpath = (delete $kv{path}) || "/";

                           if (exists $kv{domain}) {
                              $cdom = delete $kv{domain};
       
                              $cdom =~ s/^\.?/./; # make sure it starts with a "."

                              next if $cdom =~ /\.$/;
          
                              # this is not rfc-like and not netscape-like. go figure.
                              my $ndots = $cdom =~ y/.//;
                              next if $ndots < ($cdom =~ /\.[^.][^.]\.[^.][^.]$/ ? 3 : 2);
                           } else {
                              $cdom = $uhost;
                           }
       
                           # store it
                           $arg{cookie_jar}{version} = 1;
                           if (%kv) {
                              $arg{cookie_jar}{$cdom}{$cpath}{$name} = \%kv;
                           } else {
                              delete $arg{cookie_jar}{$cdom}{$cpath}{$name};
                           }

                           redo if /\G\s*,/gc;
                        }
                     }
                     $DEBUG_RECV->($_[1]{URL},$_[0],$_[1]) if defined $DEBUG_RECV;

                     if ($redirect && exists $hdr{location}) {
                        # we ignore any errors, as it is very common to receive
                        # Content-Length != 0 but no actual body
                        # we also access %hdr, as $_[1] might be an erro
                        http_request ($method => $hdr{location}, %arg, recurse => $recurse - 1, $cb);
                     } else {
                        $cb->($_[0], $_[1]);
                     }
                  };

                  my $len = $hdr{"content-length"};

                  if (!$redirect && $arg{on_header} && !$arg{on_header}(\%hdr)) {
                     $finish->(undef, { Status => 598, Reason => "Request cancelled by on_header", URL => $url });
                  } elsif (
                     $hdr{Status} =~ /^(?:1..|[23]04)$/
                     or $method eq "HEAD"
                     or (defined $len && !$len)
                  ) {
                     # no body
                     $finish->("", \%hdr);
                  } else {
                     # body handling, four different code paths
                     # for want_body_handle, on_body (2x), normal (2x)
                     # we might read too much here, but it does not matter yet (no pers. connections)
                     if (!$redirect && $arg{want_body_handle}) {
                        $_[0]->on_eof (undef);
                        $_[0]->on_error (undef);
                        $_[0]->on_read  (undef);

                        $finish->(delete $state{handle}, \%hdr);

                     } elsif ($arg{on_body}) {
                        $_[0]->on_error (sub { $finish->(undef, { Status => 599, Reason => $_[2], URL => $url }) });
                        if ($len) {
                           $_[0]->on_eof (undef);
                           $_[0]->on_read (sub {
                              $len -= length $_[0]{rbuf};

                              $arg{on_body}(delete $_[0]{rbuf}, \%hdr)
                                 or $finish->(undef, { Status => 598, Reason => "Request cancelled by on_body", URL => $url });

                              $len > 0
                                 or $finish->("", \%hdr);
                           });
                        } else {
                           $_[0]->on_eof (sub {
                              $finish->("", \%hdr);
                           });
                           $_[0]->on_read (sub {
                              $arg{on_body}(delete $_[0]{rbuf}, \%hdr)
                                 or $finish->(undef, { Status => 598, Reason => "Request cancelled by on_body", URL => $url });
                           });
                        }
                     } else {
                        $_[0]->on_eof (undef);

                        if ($len) {
                           $_[0]->on_error (sub { $finish->(undef, { Status => 599, Reason => $_[2], URL => $url }) });
                           $_[0]->on_read (sub {
                              $finish->((substr delete $_[0]{rbuf}, 0, $len, ""), \%hdr)
                                 if $len <= length $_[0]{rbuf};
                           });
                        } else {
                           $_[0]->on_error (sub {
                              $! == Errno::EPIPE || !$!
                                 ? $finish->(delete $_[0]{rbuf}, \%hdr)
                                 : $finish->(undef, { Status => 599, Reason => $_[2], URL => $url });
                           });
                           $_[0]->on_read (sub { });
                        }
                     }
                  }
               });
            });
         };

         # now handle proxy-CONNECT method
         if ($proxy && $uscheme eq "https") {
            # oh dear, we have to wrap it into a connect request

            # maybe re-use $uauthority with patched port?
            $state{handle}->push_write ("CONNECT $uhost:$uport HTTP/1.0\015\012Host: $uhost\015\012\015\012");
            $state{handle}->push_read (line => $qr_nlnl, sub {
               $_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) (?: \s+ ([^\015\012]*) )?/ix
                  or return (%state = (), $cb->(undef, { Status => 599, Reason => "Invalid proxy connect response ($_[1])", URL => $url }));

               if ($2 == 200) {
                  $rpath = $upath;
                  &$handle_actual_request;
               } else {
                  %state = ();
                  $cb->(undef, { Status => $2, Reason => $3, URL => $url });
               }
            });
         } else {
            &$handle_actual_request;
         }

      }, $arg{on_prepare} || sub { $timeout };
   };

   defined wantarray && AnyEvent::Util::guard { %state = () }
}

=cut

our $TIMEOUT = 10;

sub decode_uri {
	my $self = shift;
	my $uri = shift;
	my $port = { http => 80, https => 443, }->{ lc $uri->scheme } or return;
	my $realport = $uri->port;
	my $host = lc $uri->host;
	warn "$host : $port";
	my $host_header = $port != $realport ? "$host:$realport" : $host;
	my $proxy;
	my ($rhost, $rport, $rscheme, $rpath); # request host, port, path
	if ($proxy) {
		($rpath, $rhost, $rport, $rscheme) = ("$uri", @$proxy);
		$rscheme = "http" unless defined $rscheme;
		# don't support https requests over https-proxy transport,
		# can't be done with tls as spec'ed, unless you double-encrypt.
		$rscheme = "http" if $uri->scheme eq "https" && $rscheme eq "https";
	} else {
		($rhost, $rport, $rscheme, $rpath) = ($host,$realport,$uri->scheme,$uri->path);
	}
	return ($rhost, $rport, $rscheme, $rpath, $host_header);
}

sub connect : method {
	my ($self,$host,$port,%args) = @_;
	# TODO:
	# * slots (max-open-con)
	# * single resolve queue
	$self->{cv}->begin;
	my %state;
	my $con = sub {
		if (my $ra = shift) {
			warn "ready to con $ra $port";
			$state{connect} = tcp_connect $ra,$port,sub {
				my $fh = shift;
				@_ = ();
				if( $fh ) {
					$args{cb}($fh);
				} else {
					$args{cb}(undef,"$!");
				}
				%state = ();
			},$args{on_prepare} || sub { $args{timeout} || $TIMEOUT };
		} else {
			$args{cb}(undef,@_);
			$self->{cv}->end;
		}
	};
	my $ip = $self->{dns}{$host};
	if ($ip) {
		push @$ip, my $ra = shift @$ip;
		$con->($ra);
	} else {
		AnyEvent::DNS::a $host, sub {
			if (@_) {
				$self->{dns}{$host} = [@_];
				$con->($_[-1]);
			} else {
				$con->(undef, "$!");
			}
		};
	}
	return defined wantarray ? AnyEvent::Util::guard { %state = (); } : undef;
}

sub req {
	my $self = shift;
	my ($method, $uri, %args) = @_;
	use URI;
	$uri = URI->new($uri) unless ref $uri;
	$uri->path('/') unless length $uri->path;
	my %state;
	my $e = sub { my ($code,$mess) = @_; %state = (); $args{cb}(undef, { Status => $code, Reason => $mess, URL => $uri }); };
	my ($host, $port, $scheme, $path, $host_header) = $self->decode_uri($uri)
		or return $e->(599);
	my $headers  = HTTP::Easy::Headers->new( { %{$self->{headers}}, host => $host_header } );
	warn "($host, $port, $scheme, $path) \n";
	my $timeout = $args{timeout} || $TIMEOUT;
	$state{connect} =
	$self->connect(
			$host, $port,
			timeout => $timeout,
			on_prepare => $args{on_prepare},
			cb => sub {
		if ($state{fh} = shift) {
			warn "connected 1";
			return unless delete $state{connect};
			warn "connected 2";
			$state{handle} = AnyEvent::Handle->new(
				fh       => $state{fh},
				timeout  => $timeout,
				peername => $host,
				#tls_ctx  => $arg{tls_ctx},
			);
			# TODO: limit KA conns
			# (re-)configure handle
			$state{handle}->on_error( sub { $e->(599, $_[2]) } );
			$state{handle}->on_eof( sub { $e->(599, "Unexpected end-of-file") } );
			$state{handle}->starttls ("connect") if $scheme eq "https";
			my $request = sub {
				warn "Run request";
				$state{handle}->starttls ("connect") if $uscheme eq "https" && !exists $state{handle}{tls};
			};
			# now handle proxy-CONNECT method
			if ($proxy && $uscheme eq "https") {
				$state{handle}->push_write ("CONNECT $uhost:$uport HTTP/1.0\015\012Host: $uhost\015\012\015\012");
				$state{handle}->push_read (line => $qr_nlnl, sub {
					$_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) (?: \s+ ([^\015\012]*) )?/ix
						or return $e->(599, "Invalid proxy connect response ($_[1])");
					if ($2 == 200) {
						$rpath = $upath;
						&$request;
					} else {
						return $e->($2,$3);
					}
				});
			} else {
				&$request;
			}
		} else {
			warn "Got error @_";
			return $e->(599,@_);
		}
		#
	})

}

sub http_request;
sub req1 {
	my $self = shift;
	my %args = @_;
	$self->{cv}->begin;
	http_request +
		( $args{form} ? 'POST' : 'GET')  => "$args{uri}",
		$args{form} ? (
			body => _postdata(@{ $args{form} }),
		) : (),
		headers => {
			%{ $self->{headers} },
			$args{form} ? ( 'content-type' => 'application/x-www-form-urlencoded' ) : (),
			%{ $args{headers} || {} }
		},
		cookie_jar => $self->{cookie},
		timeout => 10,
		$self->next_proxy(),
		cb => sub {
			push @{$self->{requests}}, join(' ',$_[1]{Status}, ':', ($args{form} ? 'POST' : 'GET'), $args{uri} );
			#$self->{requests}++;
			if( my $cookies = $_[1]{'set-cookie'} ) {
				local $self->{uri} = URI->new($_[1]{URL});
				$self->_parse_cookies($cookies);
			}
			if (exists $args{raw}) {
				$args{raw}(@_);
			} else {
				my ($body,$hdr) = @_;
				if ($hdr->{Status} =~ /^(200|302)$/) {
					$self->{uri} = URI->new($hdr->{URL});
					$self->{page} = $self->getpage;
					if (exists $hdr->{'content-encoding'}) {
						if (lc($hdr->{'content-encoding'}) eq 'gzip') {
							eval{
								my $def = Compress::Zlib::memGunzip($body);
								if (defined $def) {
									$body = $def;
									#warn "Page deflated from $hdr->{'content-encoding'}" if $self->{debug};
									1;
								} else { 0 }
							} or do {
								warn "Deflate failed: $@";
							}
						} else {
							warn "Unsupported content-encoding method: $hdr->{'content-encoding'}";
						}
					}
					warn "Req $self->{uri} / $self->{page}\n"._postdata(@{ $args{form} })."\n ok" if $self->{debug};
					$args{cb}( { body => $body, head => $hdr } );
				} else {
					$args{cb}(undef, "req($hdr->{URL}) failed: $hdr->{Status}: $hdr->{Reason}");
				}
			}
			$self->{cv}->end;
		},
	;
	return;
}

=head1 AUTHOR

Mons Anderson, C<< <mons at cpan.org> >>

=head1 ACKNOWLEDGEMENTS


=head1 LICENSE

This program is free software; you can redistribute it and/or modify it
under the terms of either: the GNU General Public License as published
by the Free Software Foundation; or the Artistic License.

=cut

1; # End of AnyEvent::UA
