/* Return an error saying we couldn't find any termcap database.  */
int
tgetent (char *buf, int *type)
{
  return -1;
}
