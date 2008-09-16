#!/usr/bin/perl

my $config=0;
my $help=0;

foreach $file (@ARGV)
{
    open (FILE, $file) || die "Can't open $file: $!\n";
    while (<FILE>) {
        if (/^[a-z]/) {
	    if ($help>0) {
		printf "\n";
	    }
	    $help=0;
	    $config=0;
	    if (/^config\s+(\w*)/) {
		$config=1;
		$config_name="CONFIG_$1";
	    }
	} else {
	    if ($config==1) {
		if (/^\s+(bool|tristate||string|int|hex)\s"+(.*)"+\s*$/) {
		    $type=$2;
		}
		if (/^\s+([-]*help[-]*)\s*$/) {
		    $help=rindex($_, $1);
		    $help_start=0;
		    printf "$type\n";
		    printf "$config_name\n";
		} else {
		    if ($help>0) {
			$line=substr($_, $help);
			if ($help_start==0) {
			    if ($line =~ /\S+/) {
				$help_start=1;
			    }
			}
			if ($help_start==1) {
			    printf "  $line";
			}
		    }
		}
	    }
	}
    }
    if ($help>0) {
	printf "\n";
    }
    close (FILE);
}
