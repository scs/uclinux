#ifndef MESSWIN_H
#define MESSWIN_H

/*#define is_blank(c) ((c)==' '||(c)=='\t'); */

char *get_alias(const char *driver_name, char *argv);
int load_image(int argc, char **argv, int j, int game_index);
void list_mess_info(const char *gamename, const char *arg, int listclones);

#endif
