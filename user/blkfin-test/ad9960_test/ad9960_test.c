#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#define CMD_READ	0
#define CMD_WRITE	1
#define CMD_DUMP	2

#define CMD_SPI_WRITE   0x1
#define CMD_GET_SCLK	0x2

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
	unsigned long sclk;

	if(argc < 3){
		printf("Usage: %s [read | write |dump] number(16~1024)\n", argv[0]);
		return 0;
	}
	
	/* n represent how many datas we want to check */
	num = atoi(argv[2]);

	if(num<16 || num > 1024){
		printf("input number error, it should be (16~1024)\n");
		return 0;
	}
	
	fd = open("/dev/ad9960", O_RDWR);

	if (fd < 0) {
		perror("Error opening /dev/ad9960");
		return(-1);
	}
	
	ioctl(fd, CMD_GET_SCLK, &sclk);
	if(sclk <= 128000000){
		printf("The system bus clock setting error, it should be larger than 128MHz\n");
		return (-1);
	}
	
	if(!strcmp(argv[1], "read"))
		command = CMD_READ;

	if(!strcmp(argv[1], "write"))
		command = CMD_WRITE;

	if (!strcmp(argv[1], "dump"))
		command = CMD_DUMP;

	switch(command){
		case CMD_READ:	/* read READ_NUM datas from PPI to buf */
				{
				ioctl(fd,CMD_SPI_WRITE,0x6003); 
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
		case CMD_DUMP: /* dump captured hex values to stdio */
				{
				  ioctl(fd, CMD_SPI_WRITE, 0x6000); //disable loop-back mode
				//config the AD9960 to do 4x decimate in CIC
				//  ioctl(fd, CMD_SPI_WRITE, 0x05FF); //detailed mode
				//  ioctl(fd, CMD_SPI_WRITE, 0x081B); //rxcic 4x
				// ioctl(fd, CMD_SPI_WRITE, 0x098B); //rxfir bypass
				// ioctl(fd, CMD_SPI_WRITE, 0x0AFD); //ppi clk

				if(read(fd,buf_hardware,READ_NUM)<0)
					perror("read error\n");
				for(i=1;i<num;i+=2){
					//dump chan1, chan2 in columns.  The current driver captures an extra
					//sample at the start, so start i=1
					printf("%4x\t%4x\n", buf_hardware[i], buf_hardware[i+1]);
				}
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

unsigned int lfsr_state;

unsigned int lfsr_load(unsigned short value)
{
  // load the lfsr state with the 14 bits 15:2
  lfsr_state = (value>>2)&0x3fff;
}
  
unsigned int lfsr_train(unsigned short value){
  //use the current state to calculate the feedback value
  lfsr_state = (~((lfsr_state & 0x0001) ^ ((lfsr_state & 0x0008)>>3))<<20) | lfsr_state;
  //shift and zero out the bit that we are going to get from the input
  lfsr_state = (lfsr_state>>1) & 0xfdfff;
  
  //now use the input to generate the unknown bit 13
  lfsr_state = lfsr_state | ((value>>2)&0x2000);

}
unsigned short lfsr_next() {
  //use the current state to calculate the feedback value
  lfsr_state = (~((lfsr_state & 0x0001) ^ ((lfsr_state & 0x0008)>>3))<<20) | lfsr_state;
  //shift
  lfsr_state = (lfsr_state>>1) & 0xfffff;
  return ((lfsr_state & 0x3fff) << 2);
}


unsigned short validate_rx_datapath(unsigned short buf_hardware[],int num)
{
	unsigned short *buf_simulation;
	int i, istart;
	int step = 1;
	int search = 0;
	int qflag=0;
	int iflag=0;
	unsigned short sample;
	unsigned short i_samp=0, q_samp=0;
	unsigned short i_samp_prev=0, q_samp_prev=0;

	for(i=3;i<READ_NUM-2;i+=step){
	  /* construct this loop to work on a sample at a time to aid porting to
	     a non-buffered system */
	  
	  //find the I/Q sample alignment
	  if (step == 1) {
	    q_samp_prev = i_samp_prev;
	    i_samp_prev = q_samp;
	    q_samp = i_samp;
	    i_samp = buf_hardware[i];
	  } else {
	    q_samp_prev = q_samp;
	    i_samp_prev = i_samp;
	    q_samp = buf_hardware[i-1];
	    i_samp = buf_hardware[i];
	  }

	  if (search == 0) {
	    if ((i_samp == qtoi(q_samp)) &&
		((q_samp&0x7ffc) == ((q_samp_prev>>1)&0x7ffc))){
	      step = 2; //change the step size once we have found the I/Q sync
	      printf("Found Q\n");
	      search ++;
	      lfsr_load(q_samp);
	    }
	  } else if (search < 8) { //use 8 I/Q samples to train the LFSR
	    lfsr_train(q_samp);
	    search ++;
	  } else { 
	    //now run and compare the received data with the expacted from the LFSR
	    unsigned short tmp = lfsr_next();
	    //printf("-- %x, %x, %x, %x\n", i_samp, q_samp, qtoi(tmp), tmp);
	    printf("%6d: I_hw:\t%4x\tI_sw:\t%4x", i, i_samp, qtoi(tmp));
	    if (i_samp != qtoi(tmp)) printf(" <== Error");
	    printf("\n");
	    printf("%6d: Q_hw:\t%4x\tQ_sw:\t%4x", i+1, q_samp, tmp);
	    if (q_samp != tmp) printf(" <== Error");
	    printf("\n");
	  }
/* 	        printf("%x, %x, %x\n", buf_hardware[i]&0x7ffc,buf_hardware[i-2], (buf_hardware[i-2]>>1)&0x7ffc);  */
/* 		if((buf_hardware[i] == qtoi(buf_hardware[i-1])) && */
/* 		   ((buf_hardware[i-1]&0x7ffc) == ((buf_hardware[i-3]>>1)&0x7ffc))){ */
/* 			if (search == 0) { */
/* 				lfsr_load(buf_hardware[i-1]); */
/* 				istart = i; */
/* 				printf("istart = %d\n", istart); */
/* 				search++; */
/* 			} else if (serach < 6) { */
/* 				lfsr_train(buf_hardware[i-1]); */
/* 				search++; */
/* 			} else { */
				
/* 			} */
//		}
	}
	
	return 0;
}
