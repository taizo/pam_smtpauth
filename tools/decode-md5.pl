#!/usr/bin/perl

use MIME::Base64 ;
use Digest::HMAC_MD5 qw(hmac_md5 hmac_md5_hex);
use Digest::MD5  qw(md5 md5_hex md5_base64);

my $encPass=decode_base64($ARGV[0]) ;
print $encPass;
