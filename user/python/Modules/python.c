/* Minimal main program -- everything is loaded from the library */

#include "Python.h"

extern DL_EXPORT(int) Py_Main(int, char **);

int
main(int argc, char **argv)
{
#ifdef notdef
	extern void __probe_stack_size(void);
        __probe_stack_size();
#endif
	return Py_Main(argc, argv);
}
