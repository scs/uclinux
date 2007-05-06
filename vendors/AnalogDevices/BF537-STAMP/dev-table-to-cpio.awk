# Convert from "device_table" syntax to something the gen_init_cpio
# utility from the kernel understands

BEGIN { ret = 0 }

{
# Make sure this is a valid line
if ($1 ~ /^#/ || NF == 0)
	next
if (NF != 10) {
	print "Invalid line:" NR " " $0
	ret = 1
	next
}

# Device table format:
#  1      2      3      4     5     6       7       8       9     10
# <name> <type> <mode> <uid> <gid> <major> <minor> <start> <inc> <count>
#       f       A regular file
#       d       Directory
#       c       Character special device file
#       b       Block special device file
#       p       Fifo (named pipe)

# gen_init_cpio format:
# file <name> <location> <mode> <uid> <gid>
# dir <name> <mode> <uid> <gid>
# nod <name> <mode> <uid> <gid> <dev_type> <maj> <min>
# pipe <name> <mode> <uid> <gid>
# slink <name> <target> <mode> <uid> <gid>
# sock <name> <mode> <uid> <gid>

if ($2 == "d") {
	print "dir " $1 " " $3 " " $4 " " $5
} else if ($2 == "c" || $2 == "b") {
	if ($8 != "0" && $8 != "-") {
		for (i = $8; i <= $10; i += $9)
			print "nod " $1 i " " $3 " " $4 " " $5 " " $2 " " $6 " " ($7 + i - 1)
	} else
		print "nod " $1 " " $3 " " $4 " " $5 " " $2 " " $6 " " $7
} else {
	print "Unhandled line:" NR " " $0
	ret = 1
}
}

END { exit ret }
