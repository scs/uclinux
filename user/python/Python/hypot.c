/* hypot() replacement */

#include "config.h"
#include "pyport.h"

float hypot(float x, float y)
{
	float yx;

	x = fabs(x);
	y = fabs(y);
	if (x < y) {
		float temp = x;
		x = y;
		y = temp;
	}
	if (x == 0.)
		return 0.;
	else {
		yx = y/x;
		return x*sqrt(1.+yx*yx);
	}
}
