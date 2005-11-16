
int main() {
	return 0;
}


/* We've got to provide an entry point that doesn't stuff around with p5 like
 * C routines tend to do.
 */
asm(    ".global lib_main\n\t"
        ".type lib_main, STT_FUNC;\n"
        "lib_main:\n\t"
	"call __init;\n\t"
        "rets = [sp++];\n\t"
        "jump.l _main;\n"
        ".size   libmain, .-libmain"
);

