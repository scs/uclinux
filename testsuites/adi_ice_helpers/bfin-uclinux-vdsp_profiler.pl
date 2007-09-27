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
	die "$0: [-v] [-h] [-d] call-trace.txt system.list user.list\n  -v = verbose output\n  -d = disassemble results\n  -h = help (This message)\n  For more info check http://docs.blackfin.uclinux.org/doku.php?id=statistical_profiling\n";
}

Usage() if $#ARGV < 2;

use vars qw/ %opt /;

use Getopt::Std;

my $opt_string = 'dhv';
getopts( "$opt_string", \%opt ) or Usage();

Usage() if $opt{h};

my $trace  = $ARGV[0];
my $smap   = $ARGV[1];
my $umap   = $ARGV[2];

my $debug = 0;

my @symsort;
my $symtab;
my $mem = {};

# Since we have a sorted trace input, this lookup returns the index of the found
# address, and that is where we start looking next time
sub lookup
{
	my $sym = hex($_[0]);
	my $index= $_[1];
	my $rval = {};

	printf("  lookup: 0x%08x : %s\n", $sym, $index) if $debug;

	foreach $i ($index .. ($#symsort - 1))
	{
		if ($sym >= $symsort[$i] && $sym <  $symsort[$i+1] ) {
			$rval->{"addr"}   = sprintf("%x", $symsort[$i]);
			$rval->{"offset"} = $sym - $symsort[$i];
			$rval->{"index"} = $i;
			if ($symsort[$i+1]) {
				$rval->{"len"} = $symsort[$i+1] - $symsort[$i];
			} else {
				$rval->{"len"} = "?";
			}
			printf("  found: %i :  addr:%s  sym:%x\n", $i, $rval->{"addr"} ,$symsort[$i]) if $debug;
			return $rval;
		}
	}
	$rval->{"addr"}   = sprintf("%08x", $symsort[$#symsort]);
	$rval->{"offset"} = $sym - $symsort[$#symsort];
	$rval->{"index"} = 0;

	return $rval;
}

my $last_file=0;
my $last_file_name="";
my $last_loc=0;
my $last_funct="";

# print out the disassembly information, if we are given it
sub dis
{
	my $dis_file = $_[0];
	my $dis_to = ($_[1]);
	my $dis_from = ($_[2]);
	my $found=0;

	if( ! $opt{d}) {
		return sprintf("\n") if ($dis_to == $dis_from);
		return sprintf("");
	}

	if ( $dis_from > $dis_to && $dis_to) {
		die "function arguments ( $dis_from -> $dis_to) are backwards\n";
	}

	if ($dis_file eq "Start_of_memory") {
		if ($dis_from == $dis_to) {
			return sprintf("UNKNOWN OPCODE\n");
		} else {
			return sprintf("");
		}
	}

	if ($dis_from + 2 == $dis_to) {
		return sprintf("");
	}

	my ($file, $funct) = split(/\:/, $dis_file);
	if ($funct eq "__plt") {
		if ($dis_from == $dis_to) {
			return sprintf("__plt section filled out at runtime\n");
		} else {
			return sprintf("");
		}
	}

	$F = $last_file;
	#printf("searching for $dis_file $dis_from -> $dis_to\n");

	if ($last_file_name eq $file) {
		#printf("set to $last_loc\n");
		seek(F, $last_loc, 0);
		if ($last_funct ne $funct) {
			my $old_loc=0;
			while (<F>) {
				$old_loc = $last_loc;
				$last_loc = tell F;
				next unless /<$funct>:/;
				last;
			}
			if ( eof ) {
				# crap - need to find things by address
				$found=0;
			} else {
				$found=1;
				$last_loc = $old_loc;
				#printf("found in old file at $last_loc\n");
			}
		} else {
			$found=1;
			$_ = <F>;
		}
	} else {
		if ($F) {
			close(F);
		}

		$last_file_name = $file;

		if ($file eq "Kernel") {
			$file="vmlinux";
		}
		if (substr($file,0,7) eq "Kernel[") {
			$file = substr($file, 7, length($file)-8);
		}

		#printf("searching for $dis_file $funct in $file lines $dis_from -> $dis_to\n");

		# find the file in the dis directory
		opendir(DIR,"./dis") or die "Can't open the ./dis directory: $!\n";
		@files = readdir(DIR) or die "Unable to read current dir:$!\n";
		closedir(DIR);

		@names = grep(/^$file/, @files);
		die "Can't find file $file for $last_file_name\n" if (! @names);

		foreach $name (@names) {
			open(F,"./dis/".$name) || die "$0: can't open $name\n";
			my $old_loc=0;
			while (<F>) {
				$old_loc = $last_loc;
				$last_loc = tell F;
				next unless /<$funct>:/;
				last;
			}
			if ( eof ) {
				close(F);
				$found = 0;
			} else {
				$found=1;
				$last_loc = $old_loc;
				#printf("Found funct in new file - $last_loc\n");
				last;
			}
		}
		$last_file = $F;
	}

	if (! $found ){
		return sprintf("missing\n");
		# some symbols are not the same as the one that objdump produces, so lets try to find it by address

	}

	$last_funct = $funct;

	#printf("position = %i '$_'\n", tell F);

	chomp;
	s,^\s+|\s+$,,g;         # strip leading and trailing spaces
	@opcode = split /\s+/;  # match addrs split(/\t/,$item);
	$opcode[0] =~ s,:,,g;
	$opcode[0] =~ s,^\s+|\s+$,,g;
	$base_addr = hex $opcode[0];
	#printf("tell = %i '$_'\n", tell F);

	my $count = 0;
	while (<F>) {
		chomp;
		s,\.\.\.,,g;            # get rid of lines of "..."
		s,^\s+|\s+$,,g;         # strip leading and trailing spaces
		if (!$_) {
			next;		# skip blanks
		}
		@opcode = split /\t/;  # match addrs split(/\t/,$item);
		$opcode[0] =~ s,:,,g;
		$opcode[0] =~ s,^\s+|\s+$,,g;
		#printf("%x %x %x $_\n", $dis_from, $base_addr, hex $opcode[0]);
		if (! $opcode[0]) {
			printf("Could not decode opcode $opcode : line $_\n");
			next;
		}
		if ( ($dis_from + $base_addr) == (hex $opcode[0])) {
			last;
		}
		if ( ($dis_from + $base_addr) < (hex $opcode[0])) {
			$last_loc = 0;
			$last_funct = "";
			return sprintf("busted\n");
			#warn "$dis_from $base_addr $opcode[0]\n";
			#die "logic in search is screwed up\n";
		}
	}
	#printf("%x %x %x\n", $base_addr, $dis_from, hex $opcode[0]);
	if ($dis_from == $dis_to) {
		#close(F);
		return sprintf(" $opcode[0] $opcode[2] \n" );
	} else {
		# we need to skip the current instruction, and not print the last.
		#printf("searching for $dis_file $funct in $file lines $dis_to -> $dis_from\n");
		while (<F>) {
			chomp;
			s,\.\.\.,,g;            # get rid of lines of "..."
			s,^\s+|\s+$,,g;         # strip leading and trailing spaces
			if ( !$_ ) {
				last;
			}
			@opcode = split /\t/;  # match addrs split(/\t/,$item);
			$opcode[0] =~ s,:,,g;
			$opcode[0] =~ s,^\s+|\s+$,,g;

			#printf("$opcode[0] %x %x %x\n", hex $opcode[0], $base_addr, $dis_to);
			if (! $opcode[0]) {
				last;
			}
			if (((hex $opcode[0]) - $base_addr) == $dis_to) {
				last;
			}
			# parrallel instructions are broken over 2 lines, don't print blanks
			if ($opcode[2]) {
				 printf("                        $opcode[0] (0x%3x):  $opcode[2]\n", (hex $opcode[0]) - $base_addr);
			}
		}
		#close(F);
		return sprintf(""); #$file $funct from %x to %x\n", $dis_from, $dis_to);
	}


}

open(M, $smap) || die "$0: can't open System.list file '$smap': $!\n";
while(<M>) {
	chomp;
	@tmp = split;
	if ($tmp[0] !~ /^[0-9a-fA-F]+$/) {
		warn "bad line in system.list: $#tmp $_\n";
	}
	$tmp[0] =~ s/^0+//g;

	if ( (! $symtab{$tmp[0]}) ) {
		if ($tmp[3] ) {
			$symtab{$tmp[0]} = "Kernel".$tmp[3].":".$tmp[2];
		} else {
			$symtab{$tmp[0]} = "Kernel:".$tmp[2];
		}
	}

	if ($tmp[2] eq "__text" ) {
		$mem->{"kernel_start"} = hex $tmp[0];
	}

	if ($tmp[2] eq "__einittext" ) {
		$mem->{"kernel_end"} = hex $tmp[0];
	}

	printf("%s\n", $symtab{$tmp[0]})  if $debug;

}
close(M);

# need to sort it, to put the reset of the module info in... 
@symsort = sort { $a <=> $b } map(hex, keys %symtab);

if (0) {
	foreach $i (0 .. ($#symsort )) {
		printf("0x%08x %s\n", $symsort[$i] , $symtab{sprintf("%x",($symsort[$i]))});
	}
}

open(M, "modules.list") || die "$0: can't modules.list file!\n";
while(<M>) {
	chomp;
	@tmp = split;
	if ($#tmp !=0 ) {
		warn "bad line in modules.list\n";
		next;
	}

#	$files=$tmp[0]."\.map$";
#	opendir(DIR, ".");
#	@files = grep(/$files/,readdir(DIR));
#	closedir(DIR);
#
#foreach $file (@files) {
#   print "$file\n";
#}
#	exit;
	{
		my $file = "./maps/$tmp[0].ko.text.map";
		warn("Loading symbols from $file\n");
		my $sym = "Kernel\\[".$tmp[0]."\\]:";
		$j = 0;
		$i = 0;
		$k = 0;
		my $offset = 0;
		if ( ! -e $file) {
			warn "Can't find file $file\n";
			next;
		}
START_OVER:
		printf("Finding %s in symsort\n",$sym) if $debug;
		foreach $j ($i .. ($#symsort )) {
			if ($symtab{sprintf("%x",($symsort[$j]))} =~ m/$sym/) {
				$i = $j;
				last;
			}
		}
		if ( $i == 0 ) {
			warn "Can't find module $tmp[0] in System map\n";
			next;
		}
		printf ("Found at %i : 0x%08x : %s\n",$i, $symsort[$i], $symtab{sprintf("%x",($symsort[$i]))}) if $debug;
		$i++;
$debug=0;
SEARCH:
		open(N, $file) || die " can't open kernel module $file: $!\n";
		while (<N>) {
			chomp;
				@tmp1 = split;
			if ( $#tmp1 != 1 ) {
				warn "bad line in $file";
				next;
			} else {
				$symbol="^".$sym.$tmp1[1]."\$";
				$j=$i-1;
				printf("Looking for %s\n", $symbol) if $debug;
				printf("Comparing at %i %s  %s\n",$j, $symbol, $symtab{sprintf("%x",($symsort[$j]))}) if $debug;
				while ( ( ! ($symtab{sprintf("%x",($symsort[$j]))} =~ m/$symbol/)) &&
					($symtab{sprintf("%x",($symsort[$j]))} =~ /$sym/) &&
					($j <= $#symsort)) {
					printf(" skipping %i %s  %s\n",$j, $symbol, $symtab{sprintf("%x",($symsort[$j]))}) if $debug;
					$j++;
				}
				if ($j >= $#symsort) {
					printf("exceeded limit\n") if $debug;
					close(N);
					last;
				}
				$symexact="^".$sym.$tmp1[1]."\$";
				if (! ($symtab{sprintf("%x",($symsort[$j]))} =~ m/$symexact/)) {
					printf ("if %s != %s\n",$symexact, $symtab{sprintf("%x",($symsort[$j]))}) if $debug;
					if ( ! $offset ) {
						$k++;
						printf("skipping no offset yet %i - %s\n", $k, $symtab{sprintf("%x",($symsort[$j]))}) if $debug;
						next;
					} else {
						if ( ! $symtab{sprintf("%x",$offset+(hex $tmp1[0]))} ) {
							printf("Need to add - 0x%08x : %s\n",$offset+(hex $tmp1[0]), "Kernel[".$tmp[0]."]:".$tmp1[1]) if $debug;
							$symtab{sprintf("%x",$offset+(hex $tmp1[0]))}="Kernel[".$tmp[0]."]:".$tmp1[1];
						} else {
							if ( $symtab{sprintf("%x",$offset+(hex $tmp1[0]))} =~ m/$symexact/) {
								printf("Error - already symbol %s at (0x%08x + 0x%08x) %s | 0x%08x : tried to add %s\n",
									$symtab{sprintf("%x",$offset+(hex $tmp1[0]))},
									$offset, hex $tmp1[0],
									sprintf("0x%08x",($offset+(hex $tmp1[0]))),
									$offset+(hex $tmp1[0]), "Kernel[".$tmp[0]."]:".$tmp1[1]);
							}
						}
						next;
					}
				} else {
					printf ("if '%s' == '%s'\n",$symexact, $symtab{sprintf("%x",($symsort[$j]))}) if $debug;
					if ( ($offset) && ($offset+(hex $tmp1[0]) != $symsort[$j] )) {
						printf("Error - Addresses don't match 0x%08x != 0x%08x\n", $offset+(hex $tmp1[0]), $symsort[$j] );
					}
				}

				if ($offset ) {
					printf("Found %s (0x%x) : %s (0x%08x)\n","Kernel[".$tmp[0]."]:".$tmp1[1], hex $tmp1[0],
						$symtab{sprintf("%x",($symsort[$j]))}, $symsort[$j]) if $debug;
					if (  $symsort[$j] != $offset + hex($tmp1[0])) {
						printf("Not at same address\n");
					}
					next;
				} else {
					$offset = (hex sprintf("%x",($symsort[$j]))) - (hex $tmp1[0]);
					printf("Offset for %s = 0x%08x\n", $file, $offset) if $debug;
					close(N);
					goto SEARCH;
				}
			}
		}
		close (N);
		printf("Done - Offset = 0x%08x\n", $offset) if $debug;
		if ( ! $offset ) {
			printf ("Never found any - %s %i\n", $file, $i) if $debug;
			$i++;
			foreach $j ($i .. ($#symsort )) {
				if ($symtab{sprintf("%x",($symsort[$j]))} =~ /$sym/) {
					$i = $j;
					last;
				}
			}
			printf("done %i %i %s\n",$i, $j, $symtab{sprintf("%x",($symsort[$i]))}) if $debug;

			if ( $i >= $#symsort ) {
				printf("Skipping %s - could not find it in kernel symbols\n", $tmp[0]);
				next;
			}
			goto SEARCH
		}
	}
}
close (M);

if (0) {
	@symsort = sort { $a <=> $b } map(hex, keys %symtab);
	foreach $i (0 .. ($#symsort )) {
		printf("%x %s\n", $symsort[$i] , $symtab{sprintf("%x",($symsort[$i]))});
	}
}

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
	my $file = "./maps/$tmp2[$#tmp2].map";

	$symtab{$tmp1[0]} = $tmp2[$#tmp2];
	printf("%x    %s:__begin\n",$base , $tmp2[$#tmp2]) if $debug;
	$l1_offset=0;
	if ( -e $file ) {
		warn("Loading symbols from $file\n");
		my $L1_start = 0;
		open(N, $file) || die " can't open app.map file $file: $!\n";
		$symtab{$tmp1[0]} = $tmp2[$#tmp2].":__plt";
		while(<N>) {
			@tmp3 = split;
			if ( $#tmp3 == 2 ) {
				$tmp3[0] =~ s/^0+//g;
				$tmp3[0] = hex $tmp3[0];
				if ($tmp3[2] =~ m/^L|LE|LS\$/ ) {
					next;
				}
				if (!($tmp3[2] =~ m/^_/ )) {
					next;
				}
				if ( $tmp3[0] < 0xffa00000 ) {
					# if it is a weak symbol, and it is already loaded, skip it
					if ( ! (($tmp3[1] eq "w" || $tmp3[1] eq "W" ) && $symtab{sprintf("%x",$base+$tmp3[0])} )) {
						printf("%x    %s:%s\n",$base+$tmp3[0] , $tmp2[$#tmp2] , $tmp3[2]) if $debug;
						$symtab{sprintf("%x",$base+$tmp3[0])} =  $tmp2[$#tmp2].":".$tmp3[2];
					}
				} else {
					if ( ! $l1_offset) {
						$application="^".$tmp2[$#tmp2]."\$";
						warn("Finding L1 for $tmp2[$#tmp2]\n");
						open (P, "./pid.list") || die "$0 can't open pid.list";
						while(<P>) {
							chomp;
							@tmp4=split;
							if ($#tmp4 != 1) {
								warn "bad line in pid.list";
								next;
							}
							if ( $tmp4[0] =~ m/$application/ ) {
								printf("%s %i\n", $tmp4[0], $tmp4[1]);
								open (Q, "./l1_sram.list") || die "$0 can't open ./l1_sram.list";
								while(<Q>) {
									chomp;
									@tmp5=split;
									if ($#tmp5 != 4) {
										warn "bad line in l1_sram.list\n";
										next;
									}
									if ( $tmp5[3] == $tmp4[1] && (! $l1_offset)) {
										$l1_offset=hex $tmp5[0];
										printf("found 0x%08x as offset\n", $l1_offset);
										last;
									}
								}
								close (Q);
								last;
							}
						}
						close (P);
						if ( ! $l1_offset) {
							open (Q, "./l1_sram.list") || die "$0 can't open ./l1_sram.list";
							while(<Q>) {
								chomp;
								@tmp5=split;
								if ($#tmp5 != 4) {
									warn "bad line in l1_sram.list\n";
									next;
								}
								if ( ! $l1_offset && $tmp5[3]) {
									$l1_offset=hex $tmp5[0];
								} else {
									if ( $tmp5[3] ) {
										die "I can't tell where things are mapped in L1 - sorry\n";
									}
								}
							}
							close (Q);
						}
						if ( ! $l1_offset) {
							die "I could not find an L1 offset\n";
						}
					}
					printf("0x%08x  0x%08x  %s:%s\n",$tmp3[0] , ($tmp3[0] - 0xffa00000) + $l1_offset , $tmp2[$#tmp2] , $tmp3[2]) if $debug ;
					$symtab{sprintf("%x",($tmp3[0] - 0xffa00000) + $l1_offset )} =  $tmp2[$#tmp2].":".$tmp3[2] ;
				}
			}
		}
		close (N);
	} else {
		if ( ! ($file eq "[heap].map" || $file eq ".map" ) ) {
			warn "Can't find $file\n";
		}
	}

	if ( ! $symtab{sprintf("%x",(hex $tmp1[1]) )} ) {
		$symtab{sprintf("%x",(hex $tmp1[1]) )} = "Unknown_Mapping : end of $tmp2[$#tmp2]";
	}
	printf("%x    %s:__end\n",$end , $tmp2[$#tmp2]) if $debug;

}
close(M);

if ( ! $symtab{sprintf("%x", 0xffffffff )}) {
	$symtab{sprintf("%x", 0xffffffff )} = "End_of_memory";
}

if ( ! $symtab{sprintf("%x", 0x0 )}) {
	$symtab{sprintf("%x", 0x0 )} = "Start_of_memory";
}

@symsort = sort { $a <=> $b } map(hex, keys %symtab);

#printf("start = %x  end %x\n", $mem->{"kernel_start"}, $mem->{"kernel_end"});

# testing 1 2 3 ..
# $a = "00006a3c";
# $r = lookup($a);
# $l = $r->{"addr"};
# $s = $symtab{$l};
# printf "$a -> $l -> $s+0x%x\n", $r->{"offset"};
# exit;

if (0) {
	foreach $i (0 .. ($#symsort )) {
		printf("0x%08x %s\n", $symsort[$i] , $symtab{sprintf("%x",($symsort[$i]))});
	}
}

open(T, $trace) || die "$0: can't open trace file '$trace': $!\n";
my $sum=0;
my $last_addr=0;
while(<T>)
{
	if ( /PC\[/ ) {
		chomp;
		@addrs = split /\s+/;
		$sum += $addrs[1];
		if (oct $addrs[0] < $last_addr ) {
			die "Trace $trace is not sorted\n";
		} else {
			$last_addr=oct $addrs[0];
		}
	}
}
close(T);
warn "Total number of samples = $sum\n";

open(T, $trace) || die "$0: can't open trace file '$trace': $!\n";

my $last="";
my $num=0;
my $last_index=0;
my $old_index=0;
my $file_offset = 0;
my $last_file_offset = 0;
my $foo = 0;
my $print = 0;
my $function ="";
my $position = 0;
my $r=lookup(0,$last_index);
my $disassemble_from=0;
my $disassemble_to=0;
#$debug = 1;
while(<T>)
{

#$foo++;
#if ($foo > 00 ) {
#seek( T, 0, 2);
#}

	#
	#  line starting with non-blank terminates sections
	#
	if ( /PC\[/ ) {
		chomp;
		s,PC\[,,g;			# strip 
		s,\]*,,g;
		s,^\s+|\s+$,,g;		# strip leading and trailing spaces
		@addrs = split /\s+/;	# match addrs split(/\t/,$item); 

		my $old_function=$r;

		$r = lookup($addrs[0], $last_index);

		if ($r->{"index"}) {
			$old_index=$last_index;
			$last_index=$r->{"index"} - 1;
		}

		my $s = sprintf(" %08x", (hex $r->{"addr"})) . " ". $symtab{$r->{"addr"}};
		if (! $last) {
			$last = $s;
		}
		if (! $function) {
			$function = $s;
		}
		if (! $reset_index) {
			$reset_index = $last_index;
		}

			#printf("line in  %s %8i $last $s %i $position\n", sprintf("%08x",hex $addrs[0]), $addrs[1], tell T ) if 1;
			#printf("  %06i %s %s + %s %i $file_offset $last_file_offset $last $s\n", $addrs[1], sprintf("%08x",hex $addrs[0]), $symtab{$r->{"addr"}}, sprintf("0x%x",$r->{"offset"}), tell T);
			if ($last eq $s){
				if (! $print) {
					$num = $num + $addrs[1];
				}
			} else {
				if (! $print) {
					$print = 1;
					seek(T, $file_offset, 0);
					$last_index=$old_index;
					#warn ("$file_offset $addrs[0]\n");
				} else {
					$print = 0;
					$file_offset = $position;
					#$last_index=$old_index;
					$last=$s;
					$num = $addrs[1];
					#printf("back\n");
					if ($opt{v} && $disassemble_from){
						printf("%s", dis($symtab{$old_function->{"addr"}}, 0, $old_function->{"offset"}));
					}

				}
			}
			if ($print) {
				if ($last eq $s) {
					if ($opt{v}){
						if ( $r->{"offset"} ) {
							printf("%s", dis($symtab{$r->{"addr"}}, $r->{"offset"}, $disassemble_from));
						}
						my $a = substr(sprintf("   %02.02f%%", ($addrs[1]/$num)*100), -7);
						printf("  %8i (%s)  %s (0x%03x): %s", $addrs[1], $a, sprintf("%8x",hex $addrs[0]), $r->{"offset"}, dis($symtab{$r->{"addr"}},$r->{"offset"}, $r->{"offset"}));
					$disassemble_from = $r->{"offset"};
				}
			} else {
				my $a = substr(sprintf("   %02.02f%%", ($num/$sum)*100), -7);
				printf("\n") if ($opt{v});
				my @b = split(/\s+/, $last);
				printf("  %08i (%s) 0x%s (%i) %s\n", $num, $a, $b[1], $old_function->{"len"}, $b[2]);
				$disassemble_from=0;
			}
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
	$position = tell T;
}

close(T);
my $a = substr(sprintf("   %02.02f%%", ($num/$sum)*100), -7);
printf("  %08i (%s) $last\n",$num, $a);
