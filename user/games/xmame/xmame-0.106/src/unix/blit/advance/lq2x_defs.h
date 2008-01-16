#define XQ2X_NAME(x) x##_lq2x
#define XQ2X_FUNC_NAME(x) FUNC_NAME(x##_lq2x)

/* Some glue defines, so that we can use the advancemame lookup
   tables unmodified. */
#define MUR (c[1] != c[5])
#define MDR (c[5] != c[7])
#define MDL (c[7] != c[3])
#define MUL (c[3] != c[1])

INLINE unsigned char XQ2X_FUNC_NAME(xq2x_make_mask)(interp_uint16 *c)
{
  unsigned char mask = 0;
  
  if (c[0] != c[4])
  	mask |= 1 << 0;
  if (c[1] != c[4])
  	mask |= 1 << 1;
  if (c[2] != c[4])
  	mask |= 1 << 2;
  if (c[3] != c[4])
  	mask |= 1 << 3;
  if (c[5] != c[4])
  	mask |= 1 << 4;
  if (c[6] != c[4])
  	mask |= 1 << 5;
  if (c[7] != c[4])
  	mask |= 1 << 6;
  if (c[8] != c[4])
  	mask |= 1 << 7;
  
  return mask;
}
