#include "port.h"
#ifndef WIN32
#include <unistd.h>
#endif

#include "zcav_io.h"
#include "thread.h"
#ifdef NON_UNIX
#include "getopt.h"
#endif

#define TOO_MANY_LOOPS 100

void usage()
{
  fprintf(stderr
       , "Usage: zcav [-b block-size] [-c count] [-s max-size] [-w]\n"
#ifndef NON_UNIX
         "            [-u uid-to-use:gid-to-use] [-g gid-to-use]\n"
#endif
         "            [-l log-file] [-f] file-name\n"
         "            [-l log-file [-f] file-name]...\n"
         "\n"
         "File name of \"-\" means standard input\n"
         "Count is the number of times to read the data (default 1).\n"
         "Max size is the amount of data to read from each device.\n"
         "\n"
         "Version: " BON_VERSION "\n");
  exit(1);
}

class MultiZcav : public Thread
{
public:
  MultiZcav();
  MultiZcav(int threadNum, const MultiZcav *parent);
  virtual ~MultiZcav();

  virtual int action(PVOID param);

  int runit();

  void setFileLogNames(const char *file, const char *log)
  {
    m_fileNames.push_back(file);
    m_logNames.push_back(log);
    m_readers->push_back(new ZcavRead);
  }

  void setSizes(int block_size, int chunk_size)
  {
    m_block_size = block_size;
    m_chunk_size = chunk_size;
    if(m_block_size < 1 || m_chunk_size < 1 || m_chunk_size > m_block_size)
      usage();
  }

  void setWrite(int do_write)
  {
    m_do_write = do_write;
  }

  void setLoops(int max_loops)
  {
    m_max_loops = max_loops;
    if(max_loops < 1 || max_loops > TOO_MANY_LOOPS)
      usage();
  }

  void setMaxSize(int max_size)
  {
    m_max_size = max_size;
    if(max_size < 1)
      usage();
  }

private:
  virtual Thread *newThread(int threadNum)
                  { return new MultiZcav(threadNum, this); }

  vector<const char *> m_fileNames, m_logNames;
  vector<ZcavRead *> *m_readers;

  int m_block_size, m_max_loops, m_max_size;
  int m_chunk_size, m_do_write;

  MultiZcav(const MultiZcav &m);
  MultiZcav & operator =(const MultiZcav &m);
};

MultiZcav::MultiZcav()
{
  m_block_size = 200;
  m_max_loops = 1;
  m_max_size = 0;
  m_chunk_size = DEFAULT_CHUNK_SIZE;
  m_do_write = 0;
  m_readers = new vector<ZcavRead *>;
}

MultiZcav::MultiZcav(int threadNum, const MultiZcav *parent)
 : Thread(threadNum, parent)
 , m_readers(parent->m_readers)
 , m_block_size(parent->m_block_size)
 , m_max_loops(parent->m_max_loops)
 , m_max_size(parent->m_max_size)
{
}

int MultiZcav::action(PVOID)
{
  ZcavRead *zc = (*m_readers)[getThreadNum() - 1];
  int rc = zc->Read(m_max_loops, m_max_size / m_block_size, m_write);
  zc->Close();
  return rc;
}

MultiZcav::~MultiZcav()
{
  if(getThreadNum() < 1)
  {
    while(m_readers->size())
    {
      delete m_readers->back();
      m_readers->pop_back();
    }
    delete m_readers;
  }
}

int MultiZcav::runit()
{
  unsigned int i;
  unsigned int num_threads = m_fileNames.size();
  if(num_threads < 1)
    usage();
  for(i = 0; i < num_threads; i++)
  {
    if((*m_readers)[i]->Open(NULL, m_block_size, m_fileNames[i], m_logNames[i], m_chunk_size, m_do_write))
    {
      return 1;
    }
  }
  go(NULL, num_threads);
  int res = 0;
  while(num_threads)
  {
    char c = 0;
    if(Read(&c, 1, 0) != 1)
      printf("can't read!\n");
    num_threads--;
    if(c > res)
      res = c;
  }
  return res;
}

int main(int argc, char *argv[])
{
  MultiZcav mz;

  if(argc < 2)
    usage();

#ifndef NON_UNIX
  char *userName = NULL, *groupName = NULL;
#endif
  int c;
  int do_write = 0;
  const char *log = "-";
  const char *file = "";
  while(-1 != (c = getopt(argc, argv, "-c:b:f:l:s:w"
#ifndef NON_UNIX
                                     "u:g:"
#endif
                          )) )
  {
    switch(char(c))
    {
      case 'b':
      {
        int block_size, chunk_size;
        int rc = sscanf(optarg, "%d:%d", &block_size, &chunk_size);
        if(rc == 1)
          chunk_size = DEFAULT_CHUNK_SIZE;
        else if(rc != 2)
          usage();
        mz.setSizes(block_size, chunk_size);
      }
      break;
      case 'c':
        mz.setLoops(atoi(optarg));
      break;
      case 'l':
        log = optarg;
      break;
      case 's':
        mz.setMaxSize(atoi(optarg));
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
#endif
      break;
      case 'n':
        mz.setMaxSize(atoi(optarg));
      break;
      case 'w':
        mz.setWrite(1);
        do_write = 1;
      break;
      case 'f':
      case char(1):
        mz.setFileLogNames(optarg, log);
        file = optarg;
        log = "-";
      break;
      default:
        usage();
    }
  }

#ifndef NON_UNIX
  if(userName || groupName)
  {
    if(bon_setugid(userName, groupName, false))
      return 1;
    if(userName)
      free(userName);
  }
#endif

  if(do_write)
  {
    fprintf(stderr, "Warning, writing to %s in 5 seconds.\n", file);
    sleep(5);
  }
  int rc = mz.runit();
  sleep(2); // time for all threads to complete
  return rc;
}


