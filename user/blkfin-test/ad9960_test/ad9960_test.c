#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define CMD_READ	0
#define CMD_WRITE	1

#define CMD_RX_LOOPBACK_PRBS    0x1

#define READ_NUM	1024
#define WRITE_NUM	1024

unsigned short qtoi(unsigned short);
unsigned short qnext(unsigned short);
unsigned short validate_rx_datapath(unsigned short buf_hardware[],int num);

int main(int argc,char *argv[])
{
	int	fd;
	int 	retval;
	int	command;
	unsigned short buf_hardware[READ_NUM];
	int	i,num;

	if(argc < 3){
		printf("Usage: %s [read | write] number(16~1024)\n", argv[0]);
		return 0;
	}
	
	/* n represent how many datas we want to check */
	num = atoi(argv[2]);

	if(num<16 || num > 1024){
		printf("input number error, it should be (16~1024)\n");
		return 0;
	}
	
	fd = open("/dev/ad9960", O_RDWR);

	if (fd < 0)
	{
		perror("Error opening /dev/ad9960");
		return(-1);
	}
	if(!strcmp(argv[1], "read"))
		command = CMD_READ;

	if(!strcmp(argv[1], "write"))
		command = CMD_WRITE;

	switch(command){
		case CMD_READ:	/* read READ_NUM datas from PPI to buf */
				{
				ioctl(fd,CMD_RX_LOOPBACK_PRBS,0); 
				if(read(fd,buf_hardware,READ_NUM)<0)
					perror("read error\n");
				validate_rx_datapath(buf_hardware, num);
				break;
				};
		case CMD_WRITE: /* write WRITE_NUM datas from buf to PPI */
				{
				for(i=0;i<WRITE_NUM;i++)
					buf_hardware[i] = i;
				if(write(fd,buf_hardware,WRITE_NUM)<0)
					perror("write error\n");
				break;
				};
		default:
				perror("Command doesn't support\n");
	}
	retval = close(fd);
	if(retval)
		perror("ppi close error");

	return (0);
}

unsigned short qtoi(unsigned short data)
{
	unsigned short i=0;
	int n;
	/* Bit reversed from 19~6 'q' data to 6~19 'i' data */
	for(n=0;n<14;n++){
		if(data&0x004<<n)
			i |=  0x8000>>n;
		else
			i &= ~(0x8000>>n);
	}	
	return i;
}

unsigned short qnext(unsigned short q)
{	
	unsigned short qnext;
	/* Firstly, right shift 2 bits to get the real 14-bit 'q' data. */
	qnext = q>>2;
	/* 
	 * Secondly, righ shift 1 bit to get the next 'q' data.
	 * The highest bit will be handled later			
	 */
	qnext = qnext>>1;
	/* Thirdly, left shift 2 bits to get the hardware format 'q' data */
	qnext = qnext<<2;
	return qnext;
}

unsigned short validate_rx_datapath(unsigned short buf_hardware[],int num)
{
	unsigned short *buf_simulation;
	int i, qstart;
	int qflag=0;
	int iflag=0;
	/* Find the first correct PN data: 'q' */
	for(i=0;i<READ_NUM-2;i++){
		if(buf_hardware[i+1] == qtoi(buf_hardware[i])){
			qstart = i;
			printf("qstart = %d\n", qstart);
			break;
		}
	}
	
	/* Assuming data error if no correct data match in the whole buffer */
	if(i==READ_NUM){
		perror("Received data error\n");
		return 0;
	}

	buf_simulation = (unsigned short *)malloc(num*sizeof(unsigned short));

	/* Take the first correct data 'q' as the input of the software simulation */
	buf_simulation[0] = buf_hardware[qstart];
	
	/* reconstruct the pseudo-random number */
	for(i=1;i<num;i++){
		if(i%2){	/* PN 'i' data */
			buf_simulation[i] = qtoi(buf_simulation[i-1]);
		}else{			/* PN 'q' data */
			buf_simulation[i] = qnext(buf_simulation[i-2]);
			/* 
			 * We don't know the No.5 shift register is '1' or '0',
			 *  So we get the bit from the hardware buffer 
			 */
			if(buf_hardware[i+qstart]&0x8000){
				buf_simulation[i] |= 0x8000;
			}else
				buf_simulation[i] &= ~0x8000;
		}
	}

	/* Print the result list */
	printf("===============================\n");
	printf("Data-from-hardware	Data-by-simulation\n");
	
	for(i=qstart;i<qstart+num;i++) {
			if((i-qstart)%2){	/* print 'i' data */
				/* try to find the first unmatched data */
				if(buf_hardware[i]!=buf_simulation[i-qstart] && iflag == 0){
                                        printf("I[%d]:0x%x			0x%x====>Err: bit 0x%x\n",
                                                (i-qstart)/2+1,buf_hardware[i], buf_simulation[i-qstart],
                                                buf_hardware[i]^buf_simulation[i-qstart]);
                                        iflag = 1;
				}else{
					printf("I[%d]:0x%x			0x%x\n", 
						(i-qstart)/2+1,buf_hardware[i], buf_simulation[i-qstart]);
				}
			}else{			/* print 'q' data */
				/* try to find the first unmatched data */
				if(buf_hardware[i]!=buf_simulation[i-qstart] && qflag == 0){
					printf("Q[%d]:0x%x			0x%x====>Err: bit 0x%x\n", 
						(i-qstart)/2+1,buf_hardware[i], buf_simulation[i-qstart],
						buf_hardware[i]^buf_simulation[i-qstart]);
					qflag = 1;
				}else
					printf("Q[%d]:0x%x			0x%x\n",
                                                (i-qstart)/2+1,buf_hardware[i], buf_simulation[i-qstart]);
			}
	}
	free(buf_simulation);
	return 0;
}
