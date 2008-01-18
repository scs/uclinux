#!/usr/bin/perl
#
# Splits the list of files and outputs for makefile type files 
# wrapped at 80 chars 
# 
# Tom St Denis
@a = split(" ", $ARGV[1]);
$b = "$ARGV[0]=";
$len = length($b);
print $b;
foreach my $obj (@a) {
   $len = $len + length($obj);
   $obj =~ s/\*/\$/;
   if ($len > 100) {
      printf "\\\n";
      $len = length($obj);
   }
   print "$obj ";
}
if ($ARGV[0] eq "HEADERS") { print "testprof/tomcrypt_test.h"; }

print "\n\n";

# $Source: /cvs/libtom/libtomcrypt/parsenames.pl,v $   
# $Revision: 5081 $   
# $Date: 2007-03-16 22:47:36 +0100 (Fri, 16 Mar 2007) $ 
