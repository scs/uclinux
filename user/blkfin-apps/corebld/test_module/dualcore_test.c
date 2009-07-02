#include <linux/init.h>
#include <linux/module.h>
#include <linux/proc_fs.h>

static int *testarg = (int*)0xfeb1fffc; /* last four bytes in L2 */
struct proc_dir_entry *coreb_testarg_file;


static int read_coreb_testarg(char *page, char **start,
			      off_t offset, int count, int *eof,
			      void *data)
{
	return sprintf(page, "%d\n", *testarg);
}


static int test_init(void)
{
	*testarg = 1;

	coreb_testarg_file = create_proc_entry("coreb_testarg", 0666, NULL);
	if (coreb_testarg_file == NULL)
		return -ENOMEM;

	coreb_testarg_file->read_proc = &read_coreb_testarg;
	coreb_testarg_file->owner = THIS_MODULE;

	printk("Dual core test module inserted: set testarg = [%d]\n @ [%p]\n", *testarg, testarg);

	return 0;
}

static void test_exit(void)
{
	remove_proc_entry("coreb_testarg", NULL);
	printk("Dual core test module removed: testarg = [%d]\n", *testarg);
}

module_init(test_init);
module_exit(test_exit);
