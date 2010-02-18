#ifndef SUPPORT_H_
#define SUPPORT_H_

#define max(a, b) ((a) > (b) ? (a) : (b))
#define min(a, b) ((a) < (b) ? (a) : (b))

#define loop while (true)
#define until(a) while (!(a))

#define length(a) ((sizeof (a)) / sizeof *(a))

#define fail(e) { err = (e); goto fail; }
#define fail_m(e, m, args ...) { err = (e); trace_e(e, m, ## args); goto fail; }

#endif /* SUPPORT_H_ */
