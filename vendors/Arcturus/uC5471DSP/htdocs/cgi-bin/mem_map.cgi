#!/bin/sh

echo "Content-type: text/html"
echo
echo
echo "<html><head><title>uC5741DSP /proc/mem_map</title></head><body>"
echo "<H2>uC5741DSP /proc/mem_map</H2>"
echo

echo "<pre>"
cat /proc/mem_map
echo "</pre>"

echo
echo
echo "</body></html>"

