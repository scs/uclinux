#!/usr/bin/perl -w
#
# flat2fdpic.pl
# David Rowe
# Oct 8 2006
#

use Getopt::Long;

my $numArgs = $#ARGV + 1;
if ($numArgs < 2) {
    print "usage: ./flat2fdpic.pl inputASMfile outputASMfile";
    print " [--usep3] [--simgot=FileName] [--gf=globalsFileName]\n";
    exit;
}

# usep3 option:
#
# In G729 we use M2 to store FDPIC GOT table offset.  This is normally
# stored in P3 however P3 is not easily available in the G729 code as
# it used in many places in the G729 assembler.  During development of
# this script it was applied to some examples where P3 was available
# so this option suppresses the use of M2 and generated standard FDPIC
# code.

# simgot option:

# Simulate GOT in flat mode.
#
# Generates code very close to FDPIC, but with some minor changes to
# support testing in flat mode.  Allows us to test modified code
# incrementally in flat mode.  Produces a psuedo-GOT table as a C file.

my $usep3  = 0; # default is to generate code using M2
my $simgot = 0; # default is simulate mode off
my $globalsFile = "globals.txt";

GetOptions ("usep3" => \$usep3,
	    "simgot=s" => \$simgot,
	    "gf=s" => \$globalsFile);

if ($usep3) {
    print "P3 used - M2 not used\n";
}
else {
    print "P3 not used - M2 used\n";
}
if ($simgot) {
    print "simulating FDPIC GOT, simulated GOT table: $simgot\n";
}

# slurp global file into array -----------------------------------

{
    local( $/, *FH );
    open FH, $globalsFile or die "Can't open $globalsFile\n";
    $globals = <FH>;
    close FH;
}

# remove comment and whitespace lines and build array

$globals =~ s/^(?:#.*\n|\s*\n)//mg; 
@globals = $globals =~ /^\s*(\w*)\s*\n/mg;


# generate simulated GOT in hash

my %got = ();
my $offset = 0;
foreach (@globals) {

    # little sanity check for repeated globals
    if (defined $got{$_}) {
	print "\nError: $_ occurs more than once in $globalsFile\n";
	exit;
    }

    $got{$_} = $offset;
    $offset += 4;
}


# slurp asm file into scalar ------------------------------------

my $inFile = shift;
{
    local( $/, *FH );
    open( FH, $inFile ) or die "Can't open $inFile\n";
    $text = <FH>;
}
@text = $text =~ /^(.*)\n/mg;

# find occurences of globals in file

my $outFile = shift;

my ($state, $next_state);
my $line_num;

foreach $g (@globals) {
    $state = "looking";
    $line_num = 0;	
    $g_search = $g; $g_search =~ s/\$/\\\$/g;
    #print "looking for $g_search\n";
    @new_text = ();

    foreach (@text) {
	$line_num++;
	$next_state = $state;

	if ($state eq "looking") {
	    
	    # look for $1.H = $g + $2
 
	    if (/(.*)\.H\s*=\s*$g_search(?:;|[^\w](.*);)/) {

		# clean up extracted parameters

		$line = $_; $reg = $1; 
		if (defined $2) {
		    $add = $2; 
		} else {
		    $add = "";
		}
		
		$line =~ s/\s{2,}//g; $reg=~ s/\s*//g; 
	     
		printf "%4d %-30s %-10s %-4s", $line_num, $line, $g, $reg;

		if (length $add) {
		    $add=~ s/\s*//g;
		    $add=~ s/\+*//g;
		    printf "%-10s\n", $add;
		}
		else {
		    print "no add\n";
		}

		$next_state = "skip";
	    }    
	    else {
		push @new_text, "$_";
	    }
	}

	if ($state eq "skip") {
	    $next_state = "looking";
	    
	    # We use two temp registers, R0 and P3, which are
	    # saved and then restored.  However if one of these
	    # is the target of the load we need to choose other
	    # temp registers otherwise the values will be overwritten
	    # when the temp registers are restored.

	    $tmp_ptr = "P3"; $tmp_reg = "R0";
	    if ($reg eq "P3") {
		$tmp_ptr = "P2";
	    }
	    if ($reg eq "R0") {
		$tmp_reg = "R1";
	    }

	    # output FDPIC code

	    if ($usep3) {
		# standard FDPIC code, uses P3 for GOT ptr

		push @new_text, "\t[--SP] = $tmp_reg;";
		push @new_text, "\t$tmp_reg = [$tmp_ptr+$g\@GOT17M4];";

		if (length $add) {
		    push @new_text, "\t$tmp_reg += $add;";
		}

		push @new_text, "\t$reg = $tmp_reg";
		push @new_text, "\t$tmp_reg = [SP++];";
	    }
	    else {
                # FDPIC code for use in G729, stores GOT ptr in M2

		push @new_text, "\t[--SP] = $tmp_reg;";
		push @new_text, "\t[--SP] = $tmp_ptr;";
		push @new_text, "\t$tmp_ptr = M2;";

		if ($simgot) {
		    push @new_text, "\t$tmp_reg = [$tmp_ptr+$got{$g}]; // $g";
		} else {
		    push @new_text, "\t$tmp_reg = [$tmp_ptr+$g\@GOT17M4];";
		}

		if (length $add) {
		    if ($add < 64) {
			# use add-immediate
			push @new_text, "\t$tmp_reg += $add;";
		    } else {
			# gets a bit more complicated...
			push @new_text, "\t[--SP] = R7;";
			push @new_text, "\tR7 = $add;";
			push @new_text, "\t$tmp_reg = $tmp_reg + R7;";
			push @new_text, "\tR7 = [SP++];";
		    }
		}
		push @new_text, "\t$reg = $tmp_reg";
		push @new_text, "\t$tmp_ptr = [SP++];";
		push @new_text, "\t$tmp_reg = [SP++];";
	    }

	    # sanity check - we expect a $reg.L = $g + $add 

	    if (/(.*)\.L\s*=\s*$g_search(.*);/) {
		$reg2 = $1; $add2 = $2; 
		$reg2 =~ s/\s*//g;
		($reg eq $reg2) or die "$line_num, reg = $reg expected, $1 found\n-> $_";
		if (length $add) {
		    $add2 =~ s/\s*//g;
		    $add2 =~ s/\+*//g;
		    ($add eq $add2) or die "$line_num, add = $add expected, $2 found\n-> $_";
		}
	    }
	    else {
		die "\n$line_num, .L expected (maybe swap .H and .L lines in src file?)\n\n-> $_\n";
	    }
	}

	$state = $next_state;
    }
    @text = @new_text;
}

# now write output file

open FH, ">$outFile" or die "Can't open $outFile\n";
foreach (@text) {
    print FH "$_\n";
}
close FH;

# output simulated GOT in C file

open FH, ">$simgot" or die "Can't open $simgot\n";

$gotSize = @globals;
$gotSize *= 4;

print FH "void simgot_init() {\n";
print FH "  asm(\"\\tR0.H = _simgot;\");\n";
print FH "  asm(\"\\tR0.L = _simgot;\");\n";
print FH "  asm(\"\\tM2 = R0;\");\n";
print FH "}\n\n";

print FH "__asm__(\n";
print FH "\".global _simgot;\\n\"\n";
print FH "\".data\\n\"\n\"\t.align 4\\n\"\n\"\t.type\t_simgot, \@object\\n\"\n";
print FH "\"\t.size\t_simgot, $gotSize\\n\"\n\"_simgot:\\n\"\n";
foreach (@globals) {
    print FH "\"\t.long\t$_\\n\"\n";
}
print FH ");\n";

close FH;
