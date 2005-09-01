#include <stdlib.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define BUF_SIZE 1536

int main(int argc, char *argv[])
{
  int i2c_dev;
  int result;
  int buf[BUF_SIZE];
  printf("----------- Test I2C TWI Driver ------------\n");
  i2c_dev = open("/dev/i2c-0", O_RDWR, 0);

  if(i2c_dev == 0) printf("Unable to open i2c dev.\n"); 
  
  else{
    printf("Open device complete\n");
    result = write(i2c_dev, buf, 10);
    if(result==0)
      printf("write... [Pass]\n");
    else
      printf("write... [Fail]\n");

    result = read(i2c_dev, buf, BUF_SIZE);
    if(result==0)
      printf("read... [Pass]\n");
    else
      printf("read... [Fail]\n");

    close(i2c_dev);
  }
return 0;
}

