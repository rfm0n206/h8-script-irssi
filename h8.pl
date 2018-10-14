#!/usr/bin/perl -w
use strict;
# h8 crypto script - ported from bj(X-Chat)
# (HAX HAX HAX 2009 -lh)
#
# requirements: Crypt::CBC, Crypt::Blowfish, MIME::Base64, and Compress::Zlib
# ( perl -MCPAN -e shell ) and install any above missing cpan modules.
# crypt method: HEX(Base64((cryptloops)*(blowfish(RANDOM+Zcomp(string))+RANDOM)))
#
# To install:
# /script load h8.pl
#  and type /h8help
# To uninstall:
# /script unload h8
###################################################################################

use Crypt::CBC;
use Crypt::Blowfish;
use MIME::Base64;
use Compress::Zlib;

use Irssi::Irc;
use Irssi;
use vars qw($VERSION %IRSSI $cipher);

$VERSION = "0.0.1";
%IRSSI = ( name => 'h8',
    description => 'Blowfish IRC encryption. Supports channels, querys and dcc',
);

my $key = 'h0x0rzh1ttin' ; # Change the default key
my $header = "{h8}";
# cryptloops of val 1 should suffice...
# val of 4 can turn a single four letter word to 4 line of encryption
my $cryptloops = 1;
my $enableWildcard="yes";
my $alnum = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_';

my $gkey;
sub loadconf{
  my $fconf =Irssi::get_irssi_dir()."/h8.conf";
  my @conf;
  open (CONF, "<$fconf");
  if(!(-f CONF)){
    Irssi::print("$fconf not found, setting defaults");
    Irssi::print("Creating $fconf with defaults");
    close(CONF);
    open(CONF,">$fconf");
    print CONF "key:			$key";
    print CONF "header:			$header";
    print CONF "wildcardserver:		$enableWildcard";
    close(CONF);
    return 1;
  }
  @conf=<CONF>;
  close(CONF);
  my $current;
  foreach(@conf){
    $current = $_;
    $current =~ s/\n//g;
    if($current =~ m/key/){
      $current =~ s/.*\:[\ \t]*//;
      $key = $current;
      $gkey = $key;
    }
    if($current =~ m/header/){
      $current =~ s/.*\:[\s\t]*\{(.*)\}.*/{$1}/;
      $header = $current;
    }
    if($current =~ m/wildcardserver/){
      $current =~ s/.*\:[\ \t]*//;
      $enableWildcard = $current;
    }
  }
  Irssi::print("Config loaded");
  return 1;
}
loadconf;

my $kfile ="$ENV{HOME}/.irssi/h8.keys";
my @keys;
$gkey=$key;
my $gcryptloops=$cryptloops;

sub loadkeys{
  if(-e "$kfile"){
    open (KEYF, "<$kfile");
    @keys = <KEYF>;
    close (KEYF);
  }
  Irssi::print(scalar @keys." keys reloaded");
  return 1;
}
loadkeys;

sub getkey{
  my ($curserv, $curchan) = @_;
  my $gotkey=0;
  my $serv;
  my $chan;
  my $fkey;
  foreach(@keys){
    chomp;
    my ($serv,$chan,$fcryptloops,$fkey)=split /:/,$_,4;
    if($curserv =~ /$serv/ and $curchan eq $chan){
      $key= $fkey;
      $cryptloops=$fcryptloops;
      $gotkey=1;
    }
  }
  if(!$gotkey){
    $key=$gkey;
    $cryptloops=$gcryptloops;
  }
  #This will most likely change when Crypt::CBC changes. -lh
  $cipher=new Crypt::CBC( -key => $key, -cipher => 'Blowfish', -header => 'randomiv', undef);
}

sub setkey{
  my (undef,$server, $channel) = @_;
  return 1 if (! $channel);
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my $fcryptloops;
  my $newchan=1;
  umask(0077);
  unless ($_[0] =~ /( +\d$)/) {
    $_[0].= " $gcryptloops";
  }
  ($key, $fcryptloops) = ($_[0] =~ /(.*) +(\d)/);
  if($enableWildcard =~ /[Yy][Ee][Ss]/){
    $curserv =~ s/(.*?)\./(.*?)\./;
    Irssi::print("Server wildcards enabled");
  }
  my $line="$curserv:$curchan:$fcryptloops:$key";
  open (KEYF, ">$kfile");
  foreach(@keys) {
    s/\n//g;
    if(/^$curserv\:$curchan\:/){
      print KEYF "$line\n";
      $newchan=0;
    }else{
      print KEYF "$_\n";
    }
  }
  if($newchan){
    print KEYF "$line\n";
  }
  close (KEYF);
  loadkeys;
  Irssi::active_win()->print("$curchan key set to: $key");
  return 1;
}

sub delkey{
  my ($data, $server, $channel) = @_;
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my $serv;
  my $chan;
  open (KEYF, ">$kfile");
  foreach(@keys) {
    s/\n//g;
    ($serv,$chan)=/^(.*?)\:(.*?)\:/;
    unless ($curserv =~ /$serv/ and $curchan=~/^$chan$/){
      print KEYF "$_\n";
    }
  }
  close (KEYF);
  Irssi::active_win()->print("Key for $curchan removed");
  loadkeys;
  return 1;
}

sub showkey {
  my (undef, $server, $channel) = @_;
  return 1 if(! $channel);
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  getkey($curserv,$curchan);
  Irssi::active_win()->print("Current key: $key");
  return 1;
}

sub enc{
  my ($curserv,$curchan, $in) = @_;
  my $prng1="";
  my $prng2="";
  for (my $i=0;$i<4;$i++) {
    $prng1.=substr($alnum,int(rand(61)),1);
    $prng2.=substr($alnum,int(rand(61)),1);
  }
  getkey($curserv,$curchan);
  $cipher->start('encrypting');
  my $tbout = compress($in);
  my $i;
  for($i=0;$i<$cryptloops;$i++){
    $tbout = $prng1.$tbout;
    $tbout = $cipher->encrypt($tbout);
    $tbout .= $prng2;
    $tbout =~ s/^.{8}//;
  }
  $tbout = encode_base64($tbout);
  $tbout = unpack("H*",$tbout);
  $tbout = $header." ".$tbout;
  $tbout =~ s/=+$//;	
  $cipher->finish();
  return (length($tbout),$tbout);
}

sub irclen{
  my ($len,$curchan,$nick,$userhost) = @_;
  return ($len + length($curchan) + length("PRIVMSG : ") + length($userhost) + 1 + length($nick));
}

sub recurs{
  my ($server,$curchan,$in) = @_;
  my $half = length($in)/2-1;
  my $first = substr($in,0,$half);
  my $second = substr($in,$half,$half+3);
  if((my $pos = rindex($first," ",length($first)-8) ) != -1){
    $second = substr($first,$pos+1,length($first)-$pos) . $second;
    $first = substr($first,0,$pos);
  }
  my @a;
  my ($len,$probablyout);
  ($len,$probablyout) = enc($server->{address},$curchan,$first);
  if(irclen($len,$curchan,$server->{nick},$server->{userhost}) > 510){
    my @b=recurs($server,$curchan,$first);
    push(@a,@{$b[0]});
  }else{
    push(@a,$probablyout);
  }
  ($len,$probablyout) = enc($server->{address},$curchan,$second);
  if(irclen($len,$curchan,$server->{nick},$server->{userhost}) > 510){
    my @b = recurs($server,$curchan,$second);
    push(@a,@{$b[0]});
  }else{
    push(@a,$probablyout);
  }
  return \@a;
}

sub printout{
  my ($aref,$server,$curchan) = @_;
  foreach(@{$aref}){
    $server->command("/^msg -$server->{tag} $curchan ".$_);
  }
}

sub enhanced_printing{
  my ($server,$curchan,$in) = @_;
  my $arref = recurs($server,$curchan,$in);
  printout($arref,$server,$curchan);
}

sub h8{
  my ($data, $server, $channel) = @_;
  return 1 if(! $channel);
  my $in = $data;
  my $nick = $server->{nick};
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my ($len,$encrypted_message) = enc($curserv,$curchan,$in);
  $server->print($channel->{name}, "<$nick|{h8}> \00311$in",MSGLEVEL_CLIENTCRAP);
  $len = length($encrypted_message); #debug
  if(irclen($len,$curchan,$server->{nick},$server->{userhost}) > 510){
    enhanced_printing($server,$curchan,$data);
  }else{
    $server->command("/^msg -$server->{tag} $curchan $encrypted_message");
  }
  return 1;
}

sub infoline{
  my ($server, $data, $nick, $address) = @_;
  my ($channel,$text,$msgline,$msgnick,$curchan,$curserv);
  if(! defined($address)){
    $msgline = $data;
    $curserv = $server->{server}->{address};
    $channel = $curchan = "=".$nick;
    $msgnick = $nick;
    $server  = $server->{server};
  }else{
    ($channel, $text) = $data =~ /^(\S*)\s:(.*)/;
    $msgline = $text;
    $msgnick = $server->{nick};
    $curchan = $channel;
    $curserv = $server->{address};
  }
  if($msgline =~ m/^$header/){
    my $out = $msgline;
    $out =~ s/\0030[0-9]//g;
    $out =~ s/^$header\s*(.*)/$1/;
    if($msgnick eq $channel){
      $curchan = $channel = $nick;
    }
    getkey($curserv,$curchan);
    $cipher->start('decrypting');
    $out = pack("H*",$out);
    $out = decode_base64($out);
    my $i;
    for ($i=0;$i<$cryptloops;$i++) {
      $out = substr($out,0,(length($out)-4));
      $out = 'RandomIV'.$out;
      $out = $cipher->decrypt($out);
      $out = substr($out,4);
    }
    $out = uncompress($out);
    $cipher->finish;
    if(length($out)){
      ##$server->print($channel, "<$nick|{unh8}> \00311$out", MSGLEVEL_CLIENTCRAP);
      #Fix to light on action -neonfreon
      $server->print($channel, "<$nick|{unh8}> \00311$out", MSGLEVEL_PUBLIC);
      Irssi::signal_stop();
    }
    return 1;
  }
  return 0 ;
}

sub dccinfoline{
  my ($server, $data) = @_;
  infoline($server,$data,$server->{nick},undef);
}

my %permchans={};
sub perm{
  my ($data, $server, $channel) = @_;
  return 1 if(! $channel);
  my $curchan = $channel->{name};
  my $curserv = $server->{address}; 
  if(exists($permchans{$curserv}{$curchan}) && $permchans{$curserv}{$curchan} == 1){
    delete $permchans{$curserv}{$curchan};
    Irssi::active_win()->print("No longer crypting to $curchan on $curserv");
  }else{
    $permchans{$curserv}{$curchan} = 1;
    Irssi::active_win()->print("Crypting to $curchan on $curserv");
  }
  return 1;
}

sub myline{
  my ($data, $server, $channel) = @_;
  return 1 if(! $channel);
  my $curchan = $channel->{name};
  my $curserv = $server->{address};
  my $line = shift;
  chomp($line);
  return if(length($line) == 0);
  my $gotchan = 0;
  foreach(@keys) {
    s/\n//g;
    my ($serv,$chan,undef,undef)=split /:/;
    if(($curserv =~ /$serv/ && $curchan =~ /^$chan$/ && exists($permchans{$curserv}{$curchan}) && $permchans{$curserv}{$curchan} == 1) || (exists($permchans{$curserv}{$curchan}) && $permchans{$curserv}{$curchan} == 1)){
      $gotchan = 1;
    }
  }
  if($gotchan){
    h8($line,$server,$channel);
    Irssi::signal_stop();
    return 1;
  }
}

sub reloadconf{
  loadconf;
  loadkeys;
}

sub help{
  Irssi::print("h8 help:");
  Irssi::print("/setkey <newkey> [cryptloops] :Set a new key for the current channel");
  Irssi::print("/delkey                       :Delete the current channel key");
  Irssi::print("/showkey                      :Show the current set key");
  Irssi::print("/h8 <msg_to_crypt>            :Crypt and send msg");
  Irssi::print("/perm                         :Set flag to permanently crypt current channel");
  Irssi::print("/bconf                        :Reload h8.conf");
  return 1 ;
}

Irssi::print("h8 Blowfish IRC loaded");
Irssi::print("Type /h8help for help");
Irssi::print("cryptloops count is: $cryptloops");
Irssi::print("default key is: $key");
Irssi::signal_add("event privmsg","infoline");
Irssi::signal_add("dcc chat message","dccinfoline");
Irssi::command_bind("h8help","help");
Irssi::command_bind("setkey","setkey");
Irssi::command_bind("delkey","delkey");
Irssi::command_bind("h8","h8");
Irssi::command_bind("showkey","showkey");
Irssi::command_bind("perm","perm");
Irssi::command_bind("bconf","reloadconf");
Irssi::signal_add("send text","myline");
