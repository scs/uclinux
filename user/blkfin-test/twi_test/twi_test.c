#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>

#define I2C_SLAVE	0x0703	/* Change slave address			*/

int main(int argc, char* argv[])
{
    unsigned char outp_buf[100];
    int regval, regaddr, rc = 0;
    int i2c_fd;
    int slave_addr, wrong_addr;

    if(argc < 3) {
	    printf("Usage: twi_test 0x<correct slave addr> 0x<wrong slave addr>\n Example: 0x58 for ad5280 i2c chip on bf537-lq035 board.\n");
	    return 0;
    }

    slave_addr = strtol(argv[1], NULL, 16);
    wrong_addr = strtol(argv[2], NULL, 16);

    printf("slave addr: 0x%x\n", slave_addr);

    slave_addr >>= 1;
    
    i2c_fd = open("/dev/i2c-0", O_RDWR);

    printf("Case 1: Program with correct I2C_SLAVE address\r\n-----------------------------------------\n");
    if(ioctl(i2c_fd, I2C_SLAVE, slave_addr)<0) {/* Correct address */
	    printf("Fail to set SLAVE address\n");
	    return 0;
    }

    regaddr = 2;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Fail to get data from register %d\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    sleep(1);
    regaddr = 1;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Fail to get data from register %d\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    sleep(1);
    regaddr = 0;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Fail to get data from register %d\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    sleep(1);
    regaddr = 0x06; regval = 0x7f;
    rc = local_cam_set_register(i2c_fd, 1, regaddr, regval);
    if (rc) {
	    printf("Fail to set data to register %d\n", regaddr);
	    return 0;
    }


    sleep(1);
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Data set to register %d is wrong\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    printf("Case 2: Program with incorrect I2C_SLAVE address\r\n----------------------------------------\n");
    ioctl(i2c_fd, I2C_SLAVE, wrong_addr); /* Incorrect address */

    sleep(1);
    regaddr = 2;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (!rc) {
	    printf("Wrong addr is incorrect, read %d from reg %d\n", regval, regaddr);
	    return 0;
    }

    sleep(1);
    regaddr = 0x06; regval = 0x20;
    rc = local_cam_set_register(i2c_fd, 1, regaddr, regval);
    if (!rc) {
	    printf("Wrong addr is incorrect, write %d to reg %d\n", regval, regaddr);
	    return 0;
    }
    
    printf("Case 3: Program with correct I2C_SLAVE address\r\n------------------------------------------\n");
    ioctl(i2c_fd, I2C_SLAVE, slave_addr); /* Correct address */

    sleep(1);
    regaddr = 2;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Fail to get data from register %d\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    sleep(1);
    regaddr = 1;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Fail to get data from register %d\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    sleep(1);
    regaddr = 0;
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Fail to get data from register %d\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);

    sleep(1);
    regaddr = 0x09; regval = 0x30;
    rc = local_cam_set_register(i2c_fd, 1, regaddr, regval);
    if (rc) {
	    printf("Fail to set data to register %d\n", regaddr);
	    return 0;
    }


    sleep(1);
    rc = local_cam_get_register(i2c_fd, 1, regaddr, &regval);
    if (rc) {
	    printf("Data set to register %d is wrong\n", regaddr);
	    return 0;
    }

    printf("reg %d = 0x%x\r\n", regaddr, regval);
    
    close(i2c_fd);

    printf("TWI I2C test .... [PASS]\n");

    return 0;
}

int
local_cam_set_register(int filehandle,
                       int iDataWidth,
                       int reg_addr,
                       int val)
{
    unsigned char   buf[10];
    
    buf[0] = (unsigned char)reg_addr;

    if (iDataWidth == 1)
    {
        buf[1] = val & 0xFF;
    }
    else 
    {
        buf[1] = (val >> 8) & 0xFF;
        buf[2] = val & 0xFF;
    }

    if (write(filehandle, buf, iDataWidth + 1) == iDataWidth + 1)
    {
        if (iDataWidth == 1)
        {
            printf("local_cam_set_register: 0x%x 0x%x written\r\n", buf[0], buf[1]);
        }
        else
        {
            printf("local_cam_set_register: 0x%x 0x%x 0x%x written\r\n", buf[0], buf[1], buf[2]);
        }
        return 0;
    }

    if (iDataWidth == 1)
    {
        printf("local_cam_set_register: Error sending 0x%02x at 0x%02x, errno = %d\r\n", val, reg_addr, errno);
    }
    else
    {
        printf("local_cam_set_register: Error sending 0x%04x at 0x%02x, errno = %d\r\n", val, reg_addr, errno);
    }
    
    return (-1);
}


int
local_cam_get_register(int    filehandle,
                       int    bus_width,
                       int    reg_addr,
                       int    *val)
{
    unsigned char   regval =    reg_addr; /* Device register to access */
    unsigned char   buf[10];
    int             try_count;

    buf[0] = regval;

    if (write(filehandle, buf, 1) != 1)
    {
        printf("local_cam_get_register: error sending register address 0x%02x, errno = %d\r\n",
            regval, errno);
        return -1;
    }

    if (read(filehandle, buf, bus_width) == bus_width)
    {
        if (bus_width == 1)
        {
            *val = buf[0];
        }
        else
        {
            *val = buf[0] << 8;
            *val |= buf[1];
        }

        return 0;
    }

    printf("local_cam_get_register: error reading value @ 0x%02x, errno = %d\r\n", regval, errno);
    return -1;
}

