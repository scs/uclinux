
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <stdio.h>
#include <fcntl.h>
#include <getopt.h>

#include <strings.h>
#include "adsp-spiadc.h"

#define VERSION         "0.1"


void usage(FILE *fp, int rc)
{
    fprintf(fp, "Usage: spi_test [-h?vsc] [-c count] message string\n");
    fprintf(fp, "        -h?            this help\n");
    fprintf(fp, "        -v             print version info\n");
    fprintf(fp, "        -s             slave mode operation\n");
    fprintf(fp, "        -c count       slave mode operation receive count\n");
    exit(rc);
}

int main(int argc, char ** argv)
{
    int c, fd1,slave,size,cnt;

    char *string,*buffer;

    slave=0;

while ((c = getopt(argc, argv, "vh?sc:")) > 0) {
        switch (c) {
        case 'v':
            printf("%s: version %s\n", argv[0], VERSION);
            exit(0);
        case 's':
            slave++;
            break;
        case 'c':
            cnt = atoi(optarg);
            break;
        case 'h':
        case '?':
            usage(stdout, 0);
            break;
        default:
            fprintf(stderr, "ERROR: unkown option '%c'\n", c);
            usage(stderr, 1);
            break;
        }
    }


    string = argv[optind];
    size = strnlen (string);


        fd1 = open("/dev/spi",O_RDWR);
        if(fd1 < 0)
        {
            printf("Can't open \/dev\/spi.\n");
            return -1;
        }

        ioctl(fd1, CMD_SPI_OUT_ENABLE, 1);
        ioctl(fd1, CMD_SPI_SET_LENGTH16, 0);
        ioctl(fd1, CMD_SPI_MISO_ENABLE, 1);

        if(slave)
          {
            ioctl(fd1, CMD_SPI_SET_MASTER, 0);
            buffer = (char*) malloc(cnt+1);
            memset(buffer,0,cnt+1);
            printf("Waiting to receive %d bytes from SPI Master\n", cnt);
            read(fd1, buffer, cnt);
            printf("Last RX msg: %s \n", buffer);
            free(buffer);
          }
          else
        {
        ioctl(fd1, CMD_SPI_SET_BAUDRATE, 0x10);
        ioctl(fd1, CMD_SPI_SET_CSENABLE, 2);
        ioctl(fd1, CMD_SPI_SET_CSLOW, 2);
        ioctl(fd1, CMD_SPI_SET_MASTER, 1);

            printf("Set slave receive count to %d bytes\n", size);
            string[size]='\0';
            write(fd1, string, size+1);
            printf("Last TX msg: %s \n", string);
        }

    close(fd1);

    return 0;
}

