/* Test module for L1 attributes and stuff */

#include <linux/init.h>
#include <linux/module.h>

int a __attribute__((l1_data));
int b __attribute((section(".l1.bss")));

int c __attribute__((l1_data_B));
int d __attribute((section(".l1.bss.B")));

void l1_code_test(void) __attribute__((l1_text));

void l1_code_test(void)
{
	printk(KERN_ALERT "Code test: code function addr = 0x%p\n", l1_code_test);
}

void l1_data_a_test(void)
{
	printk(KERN_ALERT "Data bank A test: data variable addr = 0x%p, data value is %d\n", &a, a);
}

void l1_bss_a_test(void)
{
	printk(KERN_ALERT "BSS  bank A test: bss  variable addr = 0x%p, bss value is %d\n", &b, b);
}

void l1_data_b_test(void)
{
	printk(KERN_ALERT "Data bank B test: data variable addr = 0x%p, data value is %d\n", &c, c);
}

void l1_bss_b_test(void)
{
	printk(KERN_ALERT "BSS  bank B test: bss  variable addr = 0x%p, bss value is %d\n", &d, d);
}

static int hello_init(void)
{
	printk(KERN_ALERT "========Load module into L1 memory========\n");
	l1_code_test();
	l1_data_a_test();
	l1_bss_a_test();
	l1_data_b_test();
	l1_bss_b_test();
	return 0;
}

static void hello_exit(void)
{
	printk(KERN_ALERT "Goodbye, cruel world\n");
}

module_init(hello_init);
module_exit(hello_exit);

MODULE_LICENSE("Dual BSD/GPL");
