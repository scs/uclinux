#include <linux/init.h>
#include <linux/module.h>

static int *testarg = (int*)0xfeb00000;

static int test_init(void)
{
	*testarg = 1;
	printk("Dual core test module inserted: set testarg = [%d]\n @ [%p]\n", *testarg, testarg);
	
	return 0;
}

static void test_exit(void)
{
	printk("Dual core test module removed: testarg = [%d]\n", *testarg);
}

module_init(test_init);
module_exit(test_exit);
