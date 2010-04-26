package AnyEvent::UA::Req;

sub new {
	my $pk = shift;
	my ($method,$uri) = (shift,shift);
	my $self = bless {@_}, $pk;
	$self->{method} = $method;
	$self->{uri} = $uri;
	$self;
}

sub error {
	my $self = shift;
	$self->{cb}( undef, HTTP::Easy::Headers->new->HTTP(@_) );
	%$self = ();
}

package AnyEvent::UA::Con;

sub new {
	my $pk = shift;
	my $self = bless {@_}, $pk;
	$self;
}

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
use Scalar::Util 'weaken';


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
		'accept-charset'  => 'utf-8,windows-1251;q=0.7,*;q=0.7',
		'connection' => 'keep-alive',
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


our $TIMEOUT = 10;

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

our $qr_nl        = qr{\015?\012}o;
our $qr_nlnl      = qr{(?<![^\012])\015?\012}o;
our $MAX_RECURSE  =  10;

sub decode_uri {
	my $self = shift;
	my $uri = shift;
	my $port = { http => 80, https => 443, }->{ lc $uri->scheme } or return;
	my $realport = $uri->port;
	my $host = lc $uri->host;
	#warn "$host : $port";
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
	my $conkey = "$host:$port";
	my $id;
	if (exists $self->{ka}{$conkey}) {
		$id = $self->{ka}{$conkey};
		warn "Have KA for $conkey: $self->{con}{ $id }";
		push @{ $self->{con}{ $id }{r} }, AnyEvent::UA::Req->new(
			$method, $uri, %args, headers => $headers,
		);
		#$self->rr($h, $method, $uri, %args, path => $path, headers => $headers);
		$self->rr2($id);
		return;
	} else {
		# TODO:
		# push req to r, connect, handle all
		{
			weaken( my $this = $self );
			my $con = {
				host => $host,
				port => $port,
				r   => [],
				# TODO
# 				$self->{keep_alive} ? (
# 					ka  => AE::timer 300,0,sub {
# 						$self or return;
# 						delete $self->{con}{$id};
# 					},
# 				) : (),
			};
			$id = int $con;
			$con->{id} = $id;
			$self->{con}{$id} = $con;
			$self->{ka}{$conkey} = $id;
			$con->{close} = sub {
				$this or return;
				exists $this->{con}{$id} or return;
				for(@{ $this->{con}{$id}{r} }) {
					$_->error(599,$_[0]);
				}
				delete $this->{con}{$id};
			};
		}
		push @{ $self->{con}{ $id }{r} }, AnyEvent::UA::Req->new(
			$method, $uri, %args, headers => $headers,
		);
	}
	my $timeout = $args{timeout} || $TIMEOUT;
	my $proxy   = $args{proxy};#    || $PROXY;
	$state{connect} =
	$self->connect(
			$host, $port,
			timeout => $timeout,
			on_prepare => $args{on_prepare},
			cb => sub {
				if (my $fh = shift) {
					warn "connected 1";
					return unless delete $state{connect};
					warn "connected 2. id = $id";
					my $h = AnyEvent::Handle->new(
						fh       => $fh,
						timeout  => $timeout,
						peername => $host,
						on_eof     => sub { warn "EOF";    delete($self->{con}{$id})->{close}("Unexpected end-of-file") },
						on_error   => sub { warn "ERR @_"; delete($self->{con}{$id})->{close}( $_[2]); },
						#tls_ctx  => $arg{tls_ctx},
					);
					$self->{con}{$id}{h} = $h;

					# TODO: limit KA conns
					# (re-)configure handle
					my $request = sub {
						# Connection initially established
						#$self->rr($h, $method, $uri, %args, path => $path, headers => $headers);
						$self->rr2($id);
					};#END $request
					# now handle proxy-CONNECT method
					$h->starttls ("connect") if $scheme eq "https";
					if ($proxy and $scheme eq "https") {
						my $peer = (my $uhost = $uri->host).':'.$uri->port;
						$h->push_write ("CONNECT $peer HTTP/1.0\015\012Host: $uhost\015\012\015\012");
						$h->push_read (line => $qr_nlnl, sub {
							$_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) (?: \s+ ([^\015\012]*) )?/ix
								or return $e->(599, "Invalid proxy connect response ($_[1])");
							if ($2 == 200) {
								$path = $uri->path;
								$self->{con}{$id}{type} = 'raw';
								$self->rr2($id);
							} else {
								return $e->($2,$3);
							}
						});
					} else {
						$h->starttls ("connect") if $scheme eq "https" && !exists $state{handle}{tls};
						$self->rr2($id);
					}
				} else {
					warn "Got error @_";
					return $e->(599,@_);
				}
			}
	);
	return;
}

sub rr2 {
	my $self = shift;
	my $id = shift;
	return warn "no such connection $id" unless exists $self->{con}{$id};
	my $con = $self->{con}{$id};
	return warn ("Not connected yet"), unless $con->{h};
	return warn ("No more requests for $id"), $con->{h}->timeout(undef) unless @{ $con->{r} };
	#while (@{ $con->{r} }) {
		my $r = shift @{ $con->{r} };
		warn "Run request $r->{method} $r->{uri} over $con->{id}";
		if ($con->{type} eq 'proxy') {
			return $r->error(599, "Proxy not implemented");
		} else {
			my $path = $r->{uri}->path_query;
			$con->{h}->push_write (
				"$r->{method} $path HTTP/1.1\015\012" .
				$r->{headers}->encode . "\015\012" .
				(delete $r->{body})
			);
			$con->{h}->push_read (line => $qr_nl, sub {
				#return unless exists $self->{con}{$id};
				$_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) (?: \s+ ([^\015\012]*) )?/ixo
					or return $r->error( 599, "Invalid server response ($_[1])" );
					
				my $status = $2;my $reason = $3;my $http_version = $1;

				# headers, could be optimized a bit
				$con->{h}->unshift_read (line => $qr_nlnl, sub {
					my $uri = $r->{uri};
					my $method = $r->{method};
					my $hdr = HTTP::Easy::Headers->decode($_[1], base => $uri);
					$hdr->{Status} = $status;
					$hdr->{Reason} = $reason;
					# TODO: check correctness?
					#	or return $r->error(599, "Garbled response headers");
					$self->{cookie}->decode($hdr->{"set-cookie"},  host => $uri->host) if exists $hdr->{"set-cookie"};
					$self->{cookie}->decode($hdr->{"set-cookie2"}, host => $uri->host) if exists $hdr->{"set-cookie2"};
					$self->{cookie}->decode($hdr->{"set-cookie3"}, host => $uri->host) if exists $hdr->{"set-cookie3"};

					my $redirect;
					my $recurse = 0;# TODO: exists $args{recurse} ? delete $args{recurse} : $MAX_RECURSE;

					if ($recurse) {
						if ($status =~ /^30[12]$/ and $method ne "POST") {
							# apparently, mozilla et al. just change POST to GET here
							# more research is needed before we do the same
							$redirect = 1;
						}
						elsif ($status == 303) {
							# even http/1.1 is unclear on how to mutate the method
							$method = "GET" unless $method eq "HEAD";
							$redirect = 1;
						}
						elsif ($status == 307 and $method =~ /^(?:GET|HEAD)$/) {
							$redirect = 1;
						}
					}

					my $finish = sub {
						#$con->destroy if $con;
						#%state = ();

						if ($redirect && exists $hdr->{location}) {
							# we ignore any errors, as it is very common to receive
							# Content-Length != 0 but no actual body
							# we also access %hdr, as $_[1] might be an erro
							#http_request ($method => $hdr{location}, %arg, recurse => $recurse - 1, $cb);
							warn "Redirect => $hdr->{location}";
						} else {
							if (exists $_[1]{'content-encoding'}) {
								if (lc($_[1]{'content-encoding'}) =~ /^(?:x-)?gzip$/) {
									eval{
										my $def = Compress::Zlib::memGunzip($_[0]);
										if (defined $def) {
											$_[0] = $def;
											#warn "Page deflated from $hdr->{'content-encoding'}" if $self->{debug};
											1;
										} else { 0 }
									} or do {
										warn "Deflate failed: $@";
									}
								} else {
									warn "Unsupported content-encoding method: $_[1]{'content-encoding'}";
								}
							}
							$r->{cb}($_[0], $_[1]);
						}
						$self->rr2($id);
					};

					my $len = $hdr->{"content-length"};

# 					if (!$redirect && $args{on_header} && !$args{on_header}($hdr)) {
# 						$finish->(undef, { Status => 598, Reason => "Request cancelled by on_header", URL => $uri });
# 					}
# 					elsif (
					if(
						$status =~ /^(?:1..|[23]04)$/
						or $method eq "HEAD"
						or (defined $len && !$len)
					) {
						# no body
						$finish->("", $hdr);
					}
					else {
						#warn dumper $hdr,$self->{cookie};
						if (lc $hdr->{'transfer-encoding'} eq 'chunked') {
							my $body = '';
							my $get_chunk;$get_chunk = sub {
								$con->{h}->unshift_read( regex => qr{([a-f0-9]{1,32})(?:[\011\040]+[^\012]{0,255})?\015?\012}o,sub {
									my $chunk = hex($1);
									if ($chunk > 0) {
										$get_chunk->();
										#warn "need chunk $chunk";
										$_[0]->unshift_read(chunk => $chunk, sub {
											$body .= $_[1];
										});
									} else {
										undef $get_chunk;
										#warn "Got all chunks, read trailer";
										$_[0]->unshift_read(line => $qr_nlnl, sub {
											#warn "Got trailer $_[1]";
											$finish->($body,$hdr);
										});
									}
								});
							};
							$get_chunk->();
						} else {
							$_[0]->on_eof (undef);
							if ($len) {
								warn "ready for body (+$len)";
								$_[0]->on_error (sub { $finish->(undef, $hdr->HTTP(599,$_[2])) });
								$_[0]->unshift_read(chunk => $len, sub {
									$finish->($_[1],$hdr);
								});
							} else {
								warn "ready for body until eof";
								$_[0]->on_error (sub {
									$! == Errno::EPIPE || !$!
										? $finish->(delete $_[0]{rbuf}, $hdr)
										: $finish->(undef, $hdr->HTTP(599,$_[2]));
								});
								$_[0]->on_read (sub { });
							}
						}
						
					}
				});
			});
			
		}
	#}
}

sub rr { # request/response
	my $self = shift;
	my $con = shift;
	my ($method, $uri, %args) = @_;@_ = ();
	my $e = sub { my ($code,$mess) = @_; undef $con; $args{cb}(undef, { Status => $code, Reason => $mess, URL => $uri }); };
	my $recurse = exists $args{recurse} ? delete $args{recurse} : $MAX_RECURSE;
				warn "Run request $method $uri";
				
				# send request
				$con->push_write (
					"$method $args{path} HTTP/1.1\015\012"
					. $args{headers}->encode
					. "\015\012"
					. (delete $args{body})
				);
				if ($args{body_cb}) {
					my $written = 0;
					my $need = $args{headers}{"content-length"};
					$con->on_drain(sub {
						$args{body_cb}(sub {
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
									$con->on_drain(undef);
									undef $args{body_cb};
								}
								$con->push_write($chunk);
							} else {
								$con->on_drain(undef);
								undef $args{body_cb};
								if ($written < $need) {
									return $e->(599, "Insufficient ".($need-$written)." bytes data from body_cb. need $need, got $written");
								}
							}
						});
					});
					# TODO
					#%state or return;
				}

				delete $args{headers};

				# status line
				$con->push_read (line => $qr_nl, sub {
					$_[1] =~ /^HTTP\/([0-9\.]+) \s+ ([0-9]{3}) (?: \s+ ([^\015\012]*) )?/ixo
						or return $e->(599, "Invalid server response ($_[1])");
					
					my $status = $2;my $reason = $3;my $http_version = $1;

					# headers, could be optimized a bit
					$con->unshift_read (line => $qr_nlnl, sub {
						my $hdr = HTTP::Easy::Headers->decode($_[1], base => $uri);
						$self->{cookie}->decode($hdr->{"set-cookie"},  host => $uri->host) if exists $hdr->{"set-cookie"};
						$self->{cookie}->decode($hdr->{"set-cookie2"}, host => $uri->host) if exists $hdr->{"set-cookie2"};
						$self->{cookie}->decode($hdr->{"set-cookie3"}, host => $uri->host) if exists $hdr->{"set-cookie3"};
						# TODO: check correctness?
						#	or return (%state = (), $cb->(undef, { Status => 599, Reason => "Garbled response headers", URL => $url }));

						my $redirect;

						if ($recurse) {
							if ($status =~ /^30[12]$/ and $method ne "POST") {
								# apparently, mozilla et al. just change POST to GET here
								# more research is needed before we do the same
								$redirect = 1;
							}
							elsif ($status == 303) {
								# even http/1.1 is unclear on how to mutate the method
								$method = "GET" unless $method eq "HEAD";
								$redirect = 1;
							}
							elsif ($status == 307 and $method =~ /^(?:GET|HEAD)$/) {
								$redirect = 1;
							}
						}

						my $finish = sub {
							#$con->destroy if $con;
							#%state = ();

							# set-cookie processing
							$self->{cookie}->decode($_[1]{"set-cookie"}, host => $uri->host);
							#$DEBUG_RECV->($_[1]{URL},$_[0],$_[1]) if defined $DEBUG_RECV;

							if ($redirect && exists $hdr->{location}) {
								# we ignore any errors, as it is very common to receive
								# Content-Length != 0 but no actual body
								# we also access %hdr, as $_[1] might be an erro
								#http_request ($method => $hdr{location}, %arg, recurse => $recurse - 1, $cb);
								warn "Redirect => $hdr->{location}";
							} else {
								warn "OK";
								$args{cb}($_[0], $_[1]);
							}
						};

						my $len = $hdr->{"content-length"};

						if (!$redirect && $args{on_header} && !$args{on_header}($hdr)) {
							$finish->(undef, { Status => 598, Reason => "Request cancelled by on_header", URL => $uri });
						}
						elsif (
							$status =~ /^(?:1..|[23]04)$/
							or $method eq "HEAD"
							or (defined $len && !$len)
						) {
							# no body
							$finish->("", $hdr);
						}
						else {
							#warn dumper $hdr,$self->{cookie};
							if (lc $hdr->{'transfer-encoding'} eq 'chunked') {
								my $body = '';
								my $get_chunk;$get_chunk = sub {
									$con->unshift_read( regex => qr{([a-f0-9]{1,255})\015?\012},sub {
										my $chunk = hex($1);@_ = ();
										if ($chunk > 0) {
											#warn "need chunk $chunk";
											$get_chunk->();
											$con->unshift_read(chunk => $chunk, sub {
												$body .= $_[1];
											});
										} else {
											undef $get_chunk;
											warn "Got all chunks";
											$finish->($body,$hdr);
										}
									});
								};
								$get_chunk->();
							} else {
								$_[0]->on_eof (undef);
								if ($len) {
									warn "ready for body (+$len)";
									$_[0]->on_error (sub { $finish->(undef, { Status => 599, Reason => $_[2], URL => $uri }) });
									$_[0]->unshift_read(chunk => $len, sub {
										$finish->($_[1],$hdr);
									});
								} else {
									warn "ready for body until eof";
									$_[0]->on_error (sub {
										$! == Errno::EPIPE || !$!
											? $finish->(delete $_[0]{rbuf}, $hdr)
											: $finish->(undef, { Status => 599, Reason => $_[2], URL => $uri });
									});
									$_[0]->on_read (sub { });
								}
							}
							
						}
					});
				});

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
