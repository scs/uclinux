#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

int main(int argc, char* argv[])
{
	void *handle;
	char *error;
	int (*helloworld)(char *str);
	int r;
	
	handle = dlopen("libhelloworld.so", RTLD_NOW);
	if (!handle) {
		fprintf (stderr, "%s\n", dlerror());
		exit(1);
	}
	
	dlerror();    /* Clear any existing error */
	helloworld = dlsym(handle, "helloworld");
	if ((error = dlerror()) != NULL)  {
		fprintf (stderr, "%s\n", error);
		exit(1);
	}

	r = helloworld("hello\n");
	printf("get %d\n", r);
	dlclose(handle);
	
	return 0;
}

