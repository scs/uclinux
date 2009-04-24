#!/bin/bash

set -e
cd ${0%/*}

base_url="http://busybox.net/downloads/fixes-"

bdir=$(awk '$1 == "VER" { print $NF }' Makefile)
bver=${bdir#busybox-}

echo "Getting fixes for ${bver}"

url="${base_url}${bver}/"

cd ${bdir}

rm -rf hotfixes
if [[ -d .svn ]] ; then
	svn_st=$(svn st)
	if [[ -n ${svn_st} ]] ; then
		echo "ERROR: uncommitted changes"
		echo "${svn_st}"
		exit 1
	fi
fi
mkdir hotfixes
cd hotfixes
wget -nv -m -nd -np ${url}
hotfixes=$(echo *.patch)
cd ..

popts="--no-backup-if-mismatch -p1 -f"
for h in ${hotfixes} ; do
	printf "%40s: " "${h}"
	if grep -qs ${h} HOTFIXES ; then
		echo "DONE"
		continue
	fi
	if patch ${popts} --dry-run >/dev/null < hotfixes/${h} ; then
		echo "APPLYING"
		patch ${popts} >/dev/null < hotfixes/${h}
		echo ${h} >> HOTFIXES
		if [[ -d .svn ]] ; then
			svn add -q HOTFIXES
			svn commit -m "apply upstream ${url}${h}"
		fi
	else
		echo "!! FAIL !!"
	fi
done

rm -rf hotfixes
