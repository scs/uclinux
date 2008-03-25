//#define DEBUG_TCP 1

#define IRCP_DEBUG 0
#ifdef IRCP_DEBUG
#define DEBUG(n, format, args...) if(n <= IRCP_DEBUG) printf("%s(): " format, __FUNCTION__ , ##args)
#else
#define DEBUG(n, format, args...)
#endif //IRCP_DEBUG
