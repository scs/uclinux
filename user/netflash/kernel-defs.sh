#!/bin/sh
kvars=$(grep -o 'CONFIG_[^ *)]*' netflash.c | grep -v ^CONFIG_USER_ | sort -u)
for kvar in ${kvars} ; do
	eval k=\"\$$kvar\"
	[ -n "$k" ] && printf "%s " "-D$kvar"
done
exit 0
