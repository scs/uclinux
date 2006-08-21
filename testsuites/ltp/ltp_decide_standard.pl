#!/usr/bin/perl -w

my $fail = 0;

#print "$ARGV[0]\n";
#print "$ARGV[1]\n";

#open(RESULT_STD,"/home/test/logs/summary") or die "Can't open RESULT_STD: $!\n";
open(RESULT_STD,"$ARGV[0]") or die "Can't open RESULT_STD: $!\n";
my $i = 0;
my $j = 0;
my $k = 0;
@P1=@P2=@P3=@P4=();

while($line = <RESULT_STD>) {
if ($line =~/: /)
{ 
  chomp($line);
#  print "$line \n";
  ($name, $num) = split(/:/,$line);
#  print "1122$name, $num\n";
  push (@P1,$name);
  push (@P2,$num);
  $i++;
}
}

#open(RESULT,"/home/test/logs/summary.new") or die "Can't open RESULT: $!\n";
open(RESULT,"$ARGV[1]") or die "Can't open RESULT: $!\n";

while($line = <RESULT>) {
if ($line =~/: /)
{
  chomp($line);
 # print "$line \n";
  ($name, $num) = split(/:/,$line);
 # print "3344$name, $num\n";
  push (@P3,$name);
  push (@P4,$num);
  $j++;
}
}

close(RESULT_STD);
close(RESULT);


for ( $k = 0 ; $k < $j ; $k++ ) { 
if (($P1[$k] eq "  Passed Tests       ") && ($P4[$k] < $P2[$k]))
{
 $fail=1;
}
#elsif (($P1[$k] eq "  Failed Tests       ") && ($P4[$k] > $P2[$k]))
#{
#$fail=1;
#}
#elsif (($P1[$k] eq "  Broken Tests       ") && ($P4[$k] > $P2[$k]))
#{
#$fail=1;
#}
#elsif (($P1[$k] eq "  Warning Tests      ") && ($P4[$k] > $P2[$k]))
#{
#$fail=1;
#}
#elsif (($P1[$k] eq "  Crashing Tests     ") && ($P4[$k] > $P2[$k]))
#{
#$fail=1;
#}
#elsif (($P1[$k] eq "  Skipped Tests     ") && ($P4[$k] > $P2[$k]))
#{
#$fail=1;
#}  
}


if ( $fail == 0 ) {
#print "success\n";
exit 0;
return 'success';
}
elsif ($fail == 1) {
#print "test_failed\n";
exit 1;
return 'test_failed';
}


