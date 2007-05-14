#!/usr/bin/perl -w
# 
#  A program to parse profiling data, and convert the
#  numeric addresses to symbols
#
#  Based on code from: Aidan Williams <aidan@nicta.com.au>
#  Copyright 2005, National ICT Australia
#  All rights reserved.
#
#  You are welcome to use this software under the terms of the
#    "Australian Public Licence B (OZPLB) Version 1-1"
#  which may be found on the NICTA web-site:
#    http://nicta.com.au/director/commercialisation/open_source_licence.cfm
#

#
# TODO: handle addresses in L1 (need to have user space maps listed in
#       /proc/maps from userspace).
#       also note that perl seems to barf on "ffa0...." with:
#       Hexadecimal number > 0xffffffff non-portable at ../bfin-uclinux-vdsp_profiler.pl line 195, <T> line 44.
#

sub Usage
{
	die "$0: [-v] [-h] call-trace.txt system.map user.map\n  -v = verbose output\n  -h = help (This message)\n  For more info check http://docs.blackfin.uclinux.org/doku.php?id=statistical_profiling\n";
}

Usage() if $#ARGV < 2;

use vars qw/ %opt /;

use Getopt::Std;

my $opt_string = 'hv';
getopts( "$opt_string", \%opt ) or Usage();

Usage() if $opt{h};

my $trace  = $ARGV[0];
my $smap   = $ARGV[1];
my $umap   = $ARGV[2];

my $debug = 0;

my @symsort;
my $symtab;
my $mem = {};

#
#  Could make this a lot faster with a binary search..
#  (but who cares..  I have lots of GHz in my Pentium!)
#
sub lookup
{

	my $sym = hex($_[0]);
	my $rval = {};

	warn "  lookup: $_[0]/$sym\n" if $debug;

	foreach $i (0 .. ($#symsort - 1))
	{
		if ($sym >= $symsort[$i] && $sym <  $symsort[$i+1] ) {
			$rval->{"addr"}   = sprintf("%x", $symsort[$i]);
			$rval->{"offset"} = $sym - $symsort[$i];
			warn("  found: " . $rval->{"addr"} . "/$symsort[$i]\n") if $debug;
			return $rval;
		}
	}

#	warn "returning last!\n";
	$rval->{"addr"}   = sprintf("%08x", $symsort[$#symsort]);
	$rval->{"offset"} = $sym - $symsort[$#symsort];
	return $rval;
}

open(M, $smap) || die "$0: can't open System.map file '$smap': $!\n";
while(<M>) {
	chomp;
	@tmp = split;
	if ($tmp[0] !~ /^[0-9a-fA-F]+$/) {
		warn "bad line in system.map: $#tmp $_\n";
	}
	$tmp[0] =~ s/^0+//g;

	if ( !  $symtab{$tmp[0]} ) {
		if ($tmp[3] ) {
			$symtab{$tmp[0]} = "Kernel".$tmp[3].":".$tmp[2];
		} else {
			$symtab{$tmp[0]} = "Kernel:".$tmp[2];
		}
	}

	if ($tmp[2] eq "__start" ) {
		$mem->{"kernel_start"} = hex $tmp[0];
	}

	if ($tmp[2] eq "__end" ) {
		$mem->{"kernel_end"} = hex $tmp[0];
	}

	printf("%s\n", $symtab{$tmp[0]})  if $debug;

}
close(M);

# 001f8000-001fa7a4 r-xs 00000000 1f:00 211        /bin/init

open(M, $umap) || die "$0: can't open user.map file '$umap': $!\n";
while(<M>) {

	chomp;
	@tmp = split;
	if ($#tmp != 5 ) {
		warn "bad line in user.map: $#tmp $_\n";
		next;
	}
	@tmp1 = split (/-/, $tmp[0]);
	$tmp1[0] =~ s/^0+//g;
	$tmp1[1] =~ s/^0+//g;

	if ( $symtab{$tmp1[0]} ) {
		warn "Userspace and kernel overlap at $tmp1[0] $symtab{$tmp1[0]} \n";
	}
	my $base = hex $tmp1[0];
	my $end = hex $tmp1[1] ;

	@tmp2 = split (/\//, $tmp[5]);
	my $file = "$tmp2[$#tmp2].map";

	$symtab{$tmp1[0]} = $tmp2[$#tmp2];
	printf("%x    %s:__begin\n",$base , $tmp2[$#tmp2]) if $debug;
	if ( -e $file ) {
		open(N, $file) || die " can't open app.map file $file: $!\n";
		$symtab{$tmp1[0]} = $tmp2[$#tmp2].":__plt";
		while(<N>) {
			@tmp3 = split;
			if ( $#tmp3 == 2 ) {
				$tmp3[0] =~ s/^0+//g;
				$tmp3[0] = hex $tmp3[0];
				printf("%x    %s:%s\n",$base+$tmp3[0] , $tmp2[$#tmp2] , $tmp3[2]) if $debug;
				$symtab{sprintf("%x",$base+$tmp3[0])} =  $tmp2[$#tmp2].":".$tmp3[2];
			}
		}
		close (N);
	} else {
		if ( ! ($file eq "[heap].map" || $file eq ".map" ) ) {
			warn "Can't find $file\n";
		}
	}
	if ( ! $symtab{sprintf("%x",(hex $tmp1[1]) )} ) {
		$symtab{sprintf("%x",(hex $tmp1[1]) )} = "Unknown_Mapping";
	}
	printf("%x    %s:__end\n",$end , $tmp2[$#tmp2]) if $debug;

}
close(M);

@symsort = sort { $a <=> $b } map(hex, keys %symtab);

#printf("start = %x  end %x\n", $mem->{"kernel_start"}, $mem->{"kernel_end"});

# testing 1 2 3 ..
# $a = "00006a3c";
# $r = lookup($a);
# $l = $r->{"addr"};
# $s = $symtab{$l};
# printf "$a -> $l -> $s+0x%x\n", $r->{"offset"};
# exit;


open(T, $trace) || die "$0: can't open trace file '$trace': $!\n";
my $last="";
my $last_addr=0;
my $num=0;
while(<T>)
{
	#
	#  line starting with non-blank terminates sections
	#

	if ( /PC\[/ ) {
		chomp;
		s,PC\[,,g;			# strip 
		s,\]*,,g;
		s,^\s+|\s+$,,g;		# strip leading and trailing spaces
		@addrs = split /\s+/;	# match addrs split(/\t/,$item); 

		if ( (hex $addrs[0]) < $last_addr) {
			warn "$addrs[0] gt $last_addr \n";
			die "Trace $trace is not sorted\n";
		} else {
			$last_addr= hex $addrs[0];
		}

		my $r = lookup $addrs[0];
		my $s = sprintf("%08x",hex $r->{"addr"}) . " ". $symtab{$r->{"addr"}};

		if ( $last eq $s ) {
			$num = $num + $addrs[1];
			if ( $opt{v} ) {
				printf("  %06i %s %s + %s\n", $addrs[1], sprintf("%08x",hex $addrs[0]), $symtab{$r->{"addr"}}, sprintf("0x%x",$r->{"offset"}));
			}
		} else {
			if ($num) {
				printf("%08i $last\n",$num);
			}
			$num = $addrs[1];
			$last = $s;
		}
		printf("  $s\t$addrs[1]\n") if $debug;
	} else {
		if ( $num ) {
			printf("$last\t$num\n");
			$num = 0;
			$last = "";
		}
		print;
	}
}
close(T);
printf("%08i $last\n",$num);
