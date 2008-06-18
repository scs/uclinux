class Counter {
public:
	Counter(): cnt(1), max(0) {}
	int inc(int a)
		{ cnt += a; return cnt; }
private:
	unsigned cnt;
	unsigned max;
};

Counter counter; 

int a __attribute((section(".l1.data"))) = 5;

int main ()
{
	int *addr = (int *) 0xFEB1FFFC; /* last four bytes in L2 */
	a = counter.inc(a);
	a = counter.inc(a);
	
	*addr = a; /* expect a = 12 */
	
	return 0;
}
