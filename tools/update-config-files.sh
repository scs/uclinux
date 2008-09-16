#!/bin/bash

cd "${0%/*}/.."

for config in config.{sub,guess} ; do
	for file in $(find lib user -name ${config}) ; do
		if cmp -s tools/${config} ${file} ; then
			echo "Already up-to-date: ${file}"
		else
			echo "Updating ${file}"
			cp tools/${config} ${file}
		fi
	done
done
