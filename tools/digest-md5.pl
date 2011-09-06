#!/usr/bin/perl

use MIME::Base64 ;
use Digest::HMAC_MD5 qw(hmac_md5 hmac_md5_hex);
use Digest::MD5  qw(md5 md5_hex md5_base64);

$USER = $ARGV[0];
$PASS = $ARGV[1];
$CHALLENGE = $ARGV[2];

sub digest_md5 {
    my ($ticket) =@_ ;
    my %ckey = map { /^([^=]+)="?(.+?)"?$/ } split(/,/, $ticket);
    my $realm  = $ckey{realm} ;
    my $nonce  = $ckey{nonce};
    my $cnonce = &make_cnode();
    my $qop = 'auth';
    my $nc  = '00000001';
    my $uri = "smtp/$realm" ;
    my($hv, $a1, $a2);

    $hv = md5("$USER:$realm:$PASS");
    $a1 = md5_hex("$hv:$nonce:$cnonce");
    $a2 = md5_hex("AUTHENTICATE:$uri");
    $hv = md5_hex("$a1:$nonce:$nc:$cnonce:$qop:$a2");
    return qq(username="$USER",realm="$realm",nonce="$nonce",nc=$nc,cnonce="$cnonce",digest-uri="$uri",response=$hv,qop=$qop);
}

sub make_cnode {
    my $len  = 16 ;
    my $i ;
    my $s = '' ;
    for($i=0;$i<$len;$i++) { $s .=chr(rand(256)) ; }
    $s = encode_base64($s, "");
    $s =~ s/\W/X/go;
    substr($s, 0, $len);
}


$ticket = decode_base64($CHALLENGE);
($s = $ticket) =~ s/,/,\n    =>"/og ;
print "$str\n    =>$s\n" ;

print "$CHALLENGE\n    ==>" , $s , "\n" ;

my $retcode= &digest_md5($ticket) ;
($s = $retcode) =~ s/,/,\n    <=="/og ;
print "hexDigest:\n$retcode\n";
my $encPass=encode_base64($retcode,"") ;
print "encPass:\n$encPass\n";

