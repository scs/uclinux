#include "bonnie.h"

#ifdef NON_UNIX
#include "getopt.h"
#endif

#ifndef NON_UNIX
#include <unistd.h>
#include <sys/utsname.h>
#endif
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <vector>

#include "duration.h"
#include "getc_putc.h"

static void usage()
{
  fprintf(stderr, "usage:\n"
    "getc_putc [-d scratch-dir] [-s size(Kb)] [-m machine-name]\n"
    "[-u uid-to-use:gid-to-use] [-g gid-to-use]\n"
    "\nVersion: " BON_VERSION "\n");
  exit(eParam);
}

enum getc_tests_t
{
  Write = 0,
  Read,
  PutcNoTh,
  GetcNoTh,
  Putc,
  Getc,
  PutcUnlocked,
  GetcUnlocked,
  GetcTestCount
};

static void print_stat(FILE *fp, double elapsed, int test_size, bool csv);
static void print_all_res(CPCCHAR machine, FILE *fp, double *res, int size, bool csv);

#define WRITE_SIZE_FACT 32
#define GETC_SIZE_FACT 4

int main(int argc, char *argv[])
{
  int file_size = 40 << 10;
  PCCHAR dir = ".";
  bool quiet = false;
#ifndef NON_UNIX
  char *userName = NULL, *groupName = NULL;
#endif
  PCCHAR machine = NULL;

  int int_c;
  while(-1 != (int_c = getopt(argc, argv, "d:s:u:g:m:q")) )
  {
    switch(char(int_c))
    {
      case '?':
      case ':':
        usage();
      break;
      case 'd':
        dir = optarg;
      break;
      case 's':
        file_size = size_from_str(optarg, "m");
      break;
      case 'q':
        quiet = true;
      break;
      case 'm':
        machine = optarg;
      break;
#ifndef NON_UNIX
      case 'g':
        if(groupName)
          usage();
        groupName = optarg;
      break;
      case 'u':
      {
        if(userName)
          usage();
        userName = strdup(optarg);
        int i;
        for(i = 0; userName[i] && userName[i] != ':'; i++);
        if(userName[i] == ':')
        {
          if(groupName)
            usage();
          userName[i] = '\0';
          groupName = &userName[i + 1];
        }
      }
      break;
#endif
    }
  }

#ifndef NON_UNIX
  if(userName || groupName)
  {
    if(bon_setugid(userName, groupName, quiet))
      return 1;
    if(userName)
      free(userName);
  }
  else if(geteuid() == 0)
  {
    fprintf(stderr, "You must use the \"-u\" switch when running as root.\n");
    usage();
  }
#endif

  if(machine == NULL)
  {
#ifdef WIN32
    char utsBuf[MAX_COMPUTERNAME_LENGTH + 2];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if(GetComputerName(utsBuf, &size))
      machine = strdup(utsBuf);
#else
#ifdef OS2
    machine = "OS/2";
#else
    struct utsname utsBuf;
    if(uname(&utsBuf) != -1)
      machine = utsBuf.nodename;
#endif
#endif
  }

  file_size -= (file_size % WRITE_SIZE_FACT);
  file_size = file_size << 10;
  if(!file_size)
    usage();

  char *fname = new char[22 + strlen(dir)];

  sprintf(fname, "%s/getc_putc.%d", dir, getpid());

  int fd = open(fname, O_CREAT | O_TRUNC | O_RDWR, S_IRUSR | S_IWUSR);
  if(fd < 0)
  {
    fprintf(stderr, "Can't create file \"%s\".\n", fname);
    usage();
  }
  if(dup2(fd, FILE_FD) != FILE_FD)
  {
    fprintf(stderr, "Can't dup2() the file handle.");
    return 1;
  }
  close(fd);

  if(!quiet)
    printf("Extending file...");
  fflush(NULL);
  char buf[1 << 20];

  int size = 0, wrote;
  while(size < file_size)
  {
    wrote = write(FILE_FD, buf, min(sizeof(buf), (unsigned int)file_size - size));
    if(wrote < 0)
    {
      fprintf(stderr, "Can't extend file - disk full?\n");
      return 1;
    }
    size += wrote;
  }
  fsync(FILE_FD);
  volatile char c;
  int i;
  Duration dur;
  double res[GetcTestCount];

  if(lseek(FILE_FD, 0, SEEK_SET) != 0)
  {
    fprintf(stderr, "Can't seek.\n");
    return 1;
  }
  size = file_size / WRITE_SIZE_FACT;
  TEST_FUNC_WRITE("write(fd, &c, 1)", if(write(FILE_FD, (void *)&c, 1) != 1), res[Write]);
  fsync(FILE_FD);
  if(lseek(FILE_FD, 0, SEEK_SET) != 0)
  {
    fprintf(stderr, "Can't seek.\n");
    return 1;
  }
  TEST_FUNC_READ("read(fd, &c, 1)", if(read(FILE_FD, (void *)&c, 1) != 1), res[Read]);

  char *prog = new char[strlen(argv[0]) + 30];
  sprintf(prog, "%s_helper %d", argv[0], file_size);
  if(quiet)
    strcat(prog, "q");
  FILE *child = popen(prog, "r");
  if(!child)
  {
    fprintf(stderr, "Can't execute \"%s\".\n", prog);
    return 1;
  }
  if(fread(&res[PutcNoTh], sizeof(double) * 2, 1, child) != 1)
  {
    fprintf(stderr, "Can't get results from child.\n");
    return 1;
  }
  fclose(child);

  FILE *fp = fdopen(FILE_FD, "w+");
  if(!fp)
  {
    fprintf(stderr, "Can't reopen for putc.\n");
    return 1;
  }
  if(fseek(fp, 0, SEEK_SET) != 0)
  {
    fprintf(stderr, "Can't seek.\n");
    return 1;
  }
  fflush(NULL);
  size = file_size / GETC_SIZE_FACT;
  TEST_FUNC_WRITE("putc(c, fp)", if(putc(c, fp) == EOF), res[Putc]);
  if(fseek(fp, 0, SEEK_SET) != 0)
  {
    fprintf(stderr, "Can't seek.\n");
    return 1;
  }
  fflush(NULL);
  TEST_FUNC_READ("getc()", if( (c = getc(fp)) == EOF), res[Getc]);
  if(fseek(fp, 0, SEEK_SET) != 0)
  {
    fprintf(stderr, "Can't seek.\n");
    return 1;
  }
  fflush(NULL);
  size = file_size;
  TEST_FUNC_WRITE("putc_unlocked(c, fp)", if(putc_unlocked(c, fp) == EOF), res[PutcUnlocked]);
  if(fseek(fp, 0, SEEK_SET) != 0)
  {
    fprintf(stderr, "Can't seek.\n");
    return 1;
  }
  fflush(NULL);
  TEST_FUNC_READ("getc_unlocked()", if( (c = getc_unlocked(fp)) == EOF), res[GetcUnlocked]);

  if(!quiet)
    printf("done\n");
  fclose(fp);
  unlink(fname);
  size = size / 1024;
  print_all_res(machine, stderr, res, size, false);
  print_all_res(machine, stdout, res, size, true);

  return 0;
}

static void print_all_res(CPCCHAR machine, FILE *fp, double *res, int size, bool csv)
{
  if(!csv)
  {
    fprintf(fp, "Version %5s          write   read putcNT getcNT   putc   getc  putcU  getcU\n", BON_VERSION);
    fprintf(fp, "%-20s ", machine);
  }
  else
  {
    fprintf(fp, "%s", machine);
  }
  print_stat(fp, res[Write], size / WRITE_SIZE_FACT, csv);
  print_stat(fp, res[Read], size / WRITE_SIZE_FACT, csv);
  print_stat(fp, res[PutcNoTh], size, csv);
  print_stat(fp, res[GetcNoTh], size, csv);
  print_stat(fp, res[Putc], size / GETC_SIZE_FACT, csv);
  print_stat(fp, res[Getc], size / GETC_SIZE_FACT, csv);
  print_stat(fp, res[PutcUnlocked], size, csv);
  print_stat(fp, res[GetcUnlocked], size, csv);
  fprintf(fp, "\n");
}

static void print_stat(FILE *fp, double elapsed, int test_size, bool csv)
{
  if(elapsed == 0.0)
  {
    if(!csv)
      fprintf(fp, "       ");
    else
      fprintf(fp, ",");
  }
  else if(elapsed < MinTime)
  {
    if(!csv)
      fprintf(fp, " ++++++");
    else
      fprintf(fp, ",++++++");
  }
  else
  {
    double speed = double(test_size) / elapsed;
    if(!csv)
      fprintf(fp, " %6d", int(speed));
    else
      fprintf(fp, ",%d", int(speed));
  }
}
