#ifndef _STDBOOL_H
#define _STDBOOL_H

#define _Bool signed char
enum { false = 0, true = 1 };
#define bool _Bool
#define false 0
#define true 1
#define __bool_true_false_are_defined 1

#endif /* _STDBOOL_H */
