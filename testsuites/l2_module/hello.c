/* Test module for L1 attributes and stuff */

#include <linux/init.h>
#include <linux/module.h>

MODULE_LICENSE("Dual BSD/GPL");

int e __attribute__((l2_data));
int f __attribute((section(".l2.bss")));


void l2_code_test(void) __attribute__((l2_text));

void l2_code_test(void)
{
	printk(KERN_ALERT "L2 Code test: code function addr = 0x%p\n", l2_code_test);
}

void l2_data_test(void)
{
	printk(KERN_ALERT "L2 data A test: data variable addr = 0x%p, data value is %d\n", &e, e);
}

void l2_bss_test(void)
{
	printk(KERN_ALERT "L2 BSS  bank A test: bss  variable addr = 0x%p, bss value is %d\n", &f, f);
}

static int hello_init(void)
{
	printk(KERN_ALERT "========Load module into L2 memory========\n");
	l2_code_test();
	l2_data_test();
	l2_bss_test();
	return 0;
}

static void hello_exit(void)
{
	printk(KERN_ALERT "Goodbye, cruel world\n");
}

module_init(hello_init);
module_exit(hello_exit);

