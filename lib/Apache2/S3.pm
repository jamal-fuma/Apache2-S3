package Apache2::S3;

use strict;
use warnings;

use Apache2::Const -compile => qw(OK DECLINED);
use Apache2::RequestRec;
use APR::Table;
use MIME::Base64;
use Digest::SHA1;
use Digest::HMAC;
use POSIX;

our $VERSION = '0.02';

sub _signature
{
    my ($key, $secret, $data) = @_;
    return "AWS $key:".MIME::Base64::encode_base64(Digest::HMAC::hmac($data, $secret, \&Digest::SHA1::sha1), "");
}

sub handler
{
    my $r = shift;

    return Apache2::Const::DECLINED
	if $r->proxyreq;

    return Apache2::Const::DECLINED
	unless $r->method eq 'GET' or $r->dir_config('S3ReadWrite');

    my $h = $r->headers_in;
    my $uri = $r->uri;

    my %map = split /\s*(?:,|=>)\s*/, $r->dir_config("S3Map");

    # longest match first
    foreach my $base (sort { length $b <=> length $a } keys %map)
    {
	$uri =~ s|^$base/*|| or next;

	my ($bucket, $keyId, $keySecret) = split m|/|, $map{$base};
	$keyId ||= $r->dir_config("S3Key");
	$keySecret ||= $r->dir_config("S3Secret");

	my $path = "/$bucket/$uri";

	$h->{'Authorization'} = _signature $keyId, $keySecret, join "\n",
	    $r->method,
	    $h->{'Content-MD5'} || "",
	    $h->{'Content-Type'} || "",
	    $h->{'Date'} = POSIX::strftime("%a, %d %b %Y %H:%M:%S +0000", gmtime),
	    $path;

	$r->proxyreq(1);
	$r->uri("http://s3.amazonaws.com$path");
	$r->filename("proxy:http://s3.amazonaws.com$path");
	$r->handler('proxy-server');

	return Apache2::Const::OK;
    }

    return Apache2::Const::DECLINED;
}

1;
__END__
=head1 NAME

Apache2::S3 - mod_perl library for proxying requests to amazon S3

=head1 SYNOPSIS

  PerlModule Apache2::S3;
  PerlTransHandler Apache2::S3

  PerlSetVar S3Key foo
  PerlSetVar S3Secret bar
  PerlSetVar S3Map '/path/ => amazon.s3.bucket.name'

  # If you want to support non-GET requests
  PerlSetVar S3ReadWrite 1

=head1 DESCRIPTION

This module will map requests for URLs on your server into proxy
requests to the Amazon S3 service, adding authentication headers
along the way to permit access to non-public resources.

It doesn't actually do any proxying itself, rather it just adds
the Authorization header and sets the request up for mod_proxy.
Therefore you will need to enable mod_proxy like so:

  ProxyRequests on

If you permit modification requests (PUT/DELETE) using the
S3ReadWrite feature then it is quite important that you protect
the url from untrusted requests using something like the following
on Apache 2.2:

  <Proxy *>
    <LimitExcept GET>
      Order deny,allow
      Deny from all
      Allow from localhost
    </LimitExcept>
  </Proxy>

=head1 SEE ALSO

  Apache::PassThru from Chapter 7 of "Writing Apache Modules with Perl and C"
  http://www.modperl.com

  Amazon S3 API
  http://developer.amazonwebservices.com/connect/entry.jspa?entryID=123

=head1 AUTHOR

Iain Wade, E<lt>iwade@optusnet.com.auE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2007 by Iain Wade

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.8 or,
at your option, any later version of Perl 5 you may have available.

=cut
