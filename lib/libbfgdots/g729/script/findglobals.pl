#!/usr/bin/perl -w
# findglobals.pl
#
# David Rowe
# 11 Oct 2006
#
# Scans as files for globals to build gloabls.txt file.  Not
# perfect, but useful as a starting point.  globals.txt then
# requires some manual editing, for example in response to
# error messages as files are converted.

# slurp asm file into array -----------------------------------

my $fileName = shift;

{
    local( $/, *FH );
    open FH, $fileName or die "Can't open $fileName\n";
    $text = <FH>;
    close FH;
}

@t = $text =~ /^\s*(.*):.*\n/mg;
foreach (@t) {
    print "$_\n";
}


