
/* This includes the memory location and the functions for the success and failure for the LTP testcases and the customised testcases */

//volatile unsigned long *p_tr = (unsigned long *)0x6000000;
//volatile unsigned long *p1 = (unsigned long *)0x6000004;

static  unsigned long v1;
static  unsigned long v2;

static volatile unsigned long *p_tr=&v1;
static volatile unsigned long *p1=&v2;

FILE *fp;
FILE *fp1;
FILE *fp2;

int fail;
int pass;

void print_init();
void print_pass();
void print_fail();
void print_end();

void print_init()
{
	if((fp = fopen("/bin/TestResults.log","a+")) == NULL)
		printf("Error in opening TestResults.log\n");

   	if((fp1 = fopen("/bin/TestFailed.log","a+")) == NULL )
		printf("Error in opening TestFialed.log\n");

   	if((fp2 = fopen("/bin/TestOverall.log","a+")) == NULL )
		printf("Error in opening TestOverall.log\n");

return;

}

void print_pass()
{
	pass = *p_tr;
	*p_tr = ++pass;
 return;		
}

void print_fail()
{
	fail = *p1;
	*p1 = ++fail;
	
 return;	
}

void print_end()
{
   fprintf(fp2, "Total Pass :%d Total Fail :%d",*p_tr,*p1);
	fclose(fp);
	fclose(fp1);
	fclose(fp2);
	
 return;
}
