#!/bin/sh

cat > .endian.c << EOCP
short ascii_mm[] = { 0x4249, 0x4765, 0x6E44, 0x6961, 0x6E53, 0x7953, 0 };
short ascii_ii[] = { 0x694C, 0x5454, 0x656C, 0x6E45, 0x6944, 0x6E61, 0 };
void _ascii() { char* s = (char*) ascii_mm; s = (char*) ascii_ii; }
short ebcdic_ii[] = { 0x89D3, 0xE3E3, 0x8593, 0x95C5, 0x89C4, 0x9581, 0 };
short ebcdic_mm[] = { 0xC2C9, 0xC785, 0x95C4, 0x8981, 0x95E2, 0xA8E2, 0 };
void _ebcdic() { char* s = (char*) ebcdic_mm; s = (char*) ebcdic_ii; }
int main() { _ascii (); _ebcdic (); return 0; }
EOCP

if ${CC:-gcc} ${CFLAGS} ${CPPFLAGS} -c .endian.c -o .endian.o ; then
	if grep -qs BIGenDianSyS .endian.o ; then
		echo -DCRAMFS_BIG_ENDIAN
	elif grep -qs LiTTleEnDian .endian.o ; then
		echo -DCRAMFS_LITTLE_ENDIAN
	fi
fi

rm -f .endian.[co]
