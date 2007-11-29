/* using SQLite version 3
 *
 * Written 9/21/2004 by Clay Dowling <clay@lazarusid.com>
 *
 * Permission is granted to use this code for any purpose, public or 
 * private.  User assumes all liability for any damage that this code
 * or derivative products may cause, including destroying your hard
 * drive, making your dog bite you, or increasing global warming.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

struct user {

  int id;
  char name[41];
  char email[61];
  
};

struct item {

  int id;
  char* description;
  char externalkey[41];
  struct item* next;

};

void error_handler(sqlite3*);
struct user* user_populate(sqlite3_stmt*);
void user_delete(struct user*);
struct item* item_populate(sqlite3_stmt*, struct item*);
void item_delete(struct item*);

void print_center(char*);
void print_wishlist(struct user*, struct item*);

#define USER_SQL "SELECT id, name, email FROM user WHERE name = ?"
#define ITEM_SQL "SELECT id, externalkey, description FROM item WHERE user_id = ?"

int main(int argc, char** argv) {

  sqlite3* db;
  struct user* target;
  struct item* wishlist = NULL;
  struct sqlite3_stmt* userqry;
  struct sqlite3_stmt* itemqry;
  int i;
  int rc;

  if (argc == 1) {
    fprintf(stderr, "usage: %s name [name [name [...]]]\n",
	    argv[0]);
    return EXIT_FAILURE;
  }
  
  if (sqlite3_open("wishlist.db", &db))
    error_handler(db);
  
  
  if (sqlite3_prepare(db, USER_SQL, strlen(USER_SQL), &userqry, NULL))
    error_handler(db);
  if (sqlite3_prepare(db, ITEM_SQL, strlen(ITEM_SQL), &itemqry, NULL))
    error_handler(db);

  for (i=1; i < argc; i++) {
    if (sqlite3_bind_text(userqry, 1, argv[i], strlen(argv[i]), SQLITE_STATIC))
      error_handler(db);
    if (sqlite3_step(userqry) == SQLITE_ROW) {

      target = user_populate(userqry);
      sqlite3_reset(userqry);

      if (sqlite3_bind_int(itemqry, 1, target->id))
	error_handler(db);
      while((rc = sqlite3_step(itemqry)) == SQLITE_ROW) 
	wishlist = item_populate(itemqry, wishlist);

      sqlite3_reset(itemqry);

      print_wishlist(target, wishlist);
      user_delete(target);
      item_delete(wishlist);
      wishlist = NULL;

    }
    else 
      fprintf(stderr, "User %s not found.\n", argv[i]);

  }		  

  sqlite3_finalize(userqry);
  sqlite3_finalize(itemqry);

  return EXIT_SUCCESS;

}
		
void print_center(char* text) {

  int space;
  int i;

  space = 40 - strlen(text) / 2;
  for(i=0; i < space; i++) printf(" ");
  puts(text);

}

#define LINE_SIZE 65

/* start at the beggining of the line.
 * do we have LINE_SIZE characters left?
 * if yes, hunt for the last space on the line, mark it as end.
 * if no, print the rest of the text and mark no ending.
 * If we marked an end point, mark the beggining at one character past
 *   the end and start again.
 */

void print_wrapped(char* text) {

  char* cur;
  char* end;
  char* max;
  char line[LINE_SIZE];

  cur = text;
  end = text;
  while (end) {
    memset(line, 0, LINE_SIZE);
    if (strlen(cur) >= LINE_SIZE) {
      max = &cur[LINE_SIZE - 1];
      for(end = max; *end != ' ' && end > cur; --end);
      if (end > cur) strncpy(line, cur, end - cur);
      else {
	strncpy(line, cur, LINE_SIZE - 1);
	end = max;
      }
    }
    else {
      strcpy(line, cur);
      end = NULL;
    }
    puts(line);
    if (end) {
      cur = end;
      cur++;
    }
  }
  
}

void print_wishlist(struct user* u, struct item* w) {

  char uid[100];
  struct item* cur;

  print_center("+----------------+");
  print_center("W I S H  L I S T");
  print_center("+----------------+");

  snprintf(uid, 100, "* %s <%s> *", u->name, u->email);
  print_center(uid);
  printf("\n");    

  for(cur = w; cur; cur = cur->next) {
    if (strlen(cur->externalkey)) 
      printf("Product Key: %s\n", cur->externalkey);
    print_wrapped(cur->description);
    if (cur->next)
      print_center("* * *");
  }

}

struct user* user_populate(sqlite3_stmt* s) {

  struct user* u;

  u = (struct user*)calloc(1, sizeof(struct user));
  u->id = sqlite3_column_int(s, 0);
  strncpy(u->name, sqlite3_column_text(s, 1), 40);
  strncpy(u->email, sqlite3_column_text(s, 2), 60);

  return u;

}

void user_delete(struct user* u) {

  if (u)
    free(u);

}

struct item* item_populate(sqlite3_stmt* s, struct item* top) {

  struct item* cur;
  struct item* i;
  int size;
  const unsigned char* hold;

  i = (struct item*)calloc(1, sizeof(struct item));
  i->id = sqlite3_column_int(s, 0);
  hold = sqlite3_column_text(s, 1);
  if (hold)
    strncpy(i->externalkey, hold, 40);
  size = sqlite3_column_bytes(s, 2);
  hold = sqlite3_column_text(s, 2);
  if (hold) {
    i->description = (char*)calloc(1, size + 1);
    strncpy(i->description, hold, size);
  }

  if (top == NULL) return i;
  for(cur = top; cur->next ; cur = cur->next);
  cur->next = i;

  return top;

}

void item_delete(struct item* top) {

  if (!top) return;

  if (top->description) {
    free(top->description);
    top->description = 0;
  }

  item_delete(top->next);
  top->next = 0;

}

void error_handler(sqlite3* db) {

  fprintf(stderr, "Error: %s\n", sqlite3_errmsg(db));
  exit(EXIT_FAILURE);

}
