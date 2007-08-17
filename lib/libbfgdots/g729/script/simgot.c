void simgot_init() {
  asm("\tR0.H = _simgot;");
  asm("\tR0.L = _simgot;");
  asm("\tM2 = R0;");
}

__asm__(
".global _simgot;\n"
".data\n"
"	.align 4\n"
"	.type	_simgot, @object\n"
"	.size	_simgot, 4\n"
"_simgot:\n"
"	.long	_data\n"
);
