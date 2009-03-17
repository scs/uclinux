/*
 * This small examples shows how to access memory directly.
 *
 * Copyright (c) 2006 Niklaus Giger <niklaus.giger at member.fsf.org>
 *
 * It will only work on PPC405GPr based custom HW board of Nestal Maschinen AG
 *
 * It should, however, be easily adapted to similar HW
 * It will scroll across 8 LEDs (interval 1/5 of second), which are mapped
 * to some bit of the GPIO of the PPC405GPr processor.
 * Compile it with at least -O to expand the inline assembler code.
 *
 * You may find another example at http://www.denx.de/wiki/bin/view/\
 *     PPCEmbedded/DeviceDrivers#Section_AccessingPeripheralsFromUserSpace
 *     Wherefrom we stole the out_32 and iounmap procedures.
 */

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <posix/time.h>
#include <posix/pthread.h>
#include <sys/mman.h>
#include <unistd.h>

#define MAP_SIZE			4096UL
#define MAP_MASK 			(MAP_SIZE - 1)

/* board specific, please put in correct values for your HW */
#define HCU3_LED_REGISTER		0xEF600700

volatile unsigned long *ledRegister;

#ifdef __PPC__
extern inline void out_32(volatile unsigned long *addr, unsigned val)
{
	/* Here we  use PPC assembler code to ensure that the IO is actually */
	/* performed before executing the next instruction. */
	/* This behaviour is also called a "memory barrier" */
	__asm__ __volatile__("stw%U0%X0 %1,%0; eieio" : "=m" (*addr)
				 : "r" (val));
}
#else
extern inline void out_32(volatile unsigned long *addr, unsigned val)
{ 
	/* Depending on your architectue you may need to add memory barriers */
	*addr = val;
}
#endif

void *mapDirectIoRegister(unsigned long addr, size_t length)
{
	void *map_base, * virtAddr;
	off_t target = ((unsigned int)addr) & ~MAP_MASK;
	int fd;
	
	if ((fd = open("/dev/mem", O_RDWR | O_SYNC)) == -1) {
		printf("/dev/mem could not be opened.\n");
		exit(1);
	}
	
	/* Map one page */
	map_base = mmap((void *)target, length, PROT_READ | PROT_WRITE, 
			MAP_SHARED, fd, target);
	if (map_base == (void *) -1) {
		printf("Memory map failed for address 0x%lx\n", addr);
		exit(1);
	}
	
	virtAddr = (void *)((unsigned long)map_base + 
			    ((unsigned long)addr & MAP_MASK));
	printf("Memory map 0x%lx -> %p offset 0x%lx virtual %p\n", 
		addr, map_base, addr & MAP_MASK, virtAddr);
	return virtAddr;
}

int iounmap(volatile void *start, size_t length)
{
	unsigned long ofs_addr;
	ofs_addr = (unsigned long)start & (getpagesize()-1);
	
	/* do some cleanup when you're done with it */
	return munmap((void*)start-ofs_addr, length+ofs_addr);
}

void sysLedSet(unsigned char value)
{
	/* board specific, please put in correct values for your HW */
	/* Here: inverse and shift the value 23 bits to the left */
        out_32(ledRegister, ( unsigned long ) ~value << 23);
}

int main(int argc, char *argv[])
{
	unsigned char j;
	int res;
	struct sched_param param;

	printf("%s: %s %s\n", __FUNCTION__, __DATE__, __TIME__ );
	param.__sched_priority = 99;
	res = pthread_setschedparam(pthread_self(),  SCHED_FIFO, &param);

	/* HW initialisation */
	ledRegister     = (unsigned long *)mapDirectIoRegister(
				HCU3_LED_REGISTER, MAP_SIZE);
	/* next we set the correct control mask in the GPIO_TCR */
	/* board specific, please put in correct values for your HW */
	ledRegister[1]  = 0x7ffe0000; /* Three State Control */

	/* Now scroll our leds and pause a little bit between */
	for (j=0; j <= 8; j++) {
		struct timespec waittime, remaining;

		waittime.tv_sec = 0;
		waittime.tv_nsec = 200*1000*1000; /* 0.2 sec in nanosecs */
		nanosleep(&waittime, &remaining);

		sysLedSet(1 << j);
	}
	iounmap((volatile void *)HCU3_LED_REGISTER, MAP_SIZE);
	printf("\n%s:done\n", __FUNCTION__); 
	return 0;
}
