int a = 2;

int main()
{
	int *addr = (int *) 0xFEB1FFFC; /* last four bytes in L2 */
	*addr = a;
	return 0;
}
